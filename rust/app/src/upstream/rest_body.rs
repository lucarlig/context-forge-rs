// SPDX-License-Identifier: Apache-2.0

use async_compression::tokio::bufread::{
    BrotliDecoder, DeflateDecoder, GzipDecoder, ZlibDecoder, ZstdDecoder,
};
use reqwest::{
    Response,
    header::{CONTENT_ENCODING, HeaderValue},
};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::{MAX_MESSAGE_BYTES, UpstreamError, read_bounded_body};

pub(super) const ACCEPTED: HeaderValue = HeaderValue::from_static("gzip, deflate, br, zstd");

enum Coding {
    Gzip,
    Deflate,
    Brotli,
    Zstd,
}

impl Coding {
    fn parse(value: &str) -> Option<Self> {
        if value.eq_ignore_ascii_case("gzip") {
            Some(Self::Gzip)
        } else if value.eq_ignore_ascii_case("deflate") {
            Some(Self::Deflate)
        } else if value.eq_ignore_ascii_case("br") {
            Some(Self::Brotli)
        } else if value.eq_ignore_ascii_case("zstd") {
            Some(Self::Zstd)
        } else {
            None
        }
    }

    async fn decode(&self, input: &[u8], limit: usize) -> Result<Vec<u8>, UpstreamError> {
        match self {
            Self::Gzip => read_decoded(GzipDecoder::new(input), limit).await,
            Self::Deflate => match read_decoded(ZlibDecoder::new(input), limit).await {
                Err(UpstreamError::Transport) => {
                    read_decoded(DeflateDecoder::new(input), limit).await
                }
                result => result,
            },
            Self::Brotli => read_decoded(BrotliDecoder::new(input), limit).await,
            Self::Zstd => {
                let mut decoder = ZstdDecoder::new_for_http(input);
                decoder.multiple_members(true);
                read_decoded(decoder, limit).await
            }
        }
    }
}

pub(super) async fn read(response: Response) -> Result<Vec<u8>, UpstreamError> {
    let codings: Vec<_> = response
        .headers()
        .get_all(CONTENT_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|value| Coding::parse(value.trim()))
        .collect();

    let mut body = read_bounded_body(response, MAX_MESSAGE_BYTES).await?;
    if body.is_empty() {
        return Ok(body);
    }
    for coding in codings.iter().rev() {
        body = coding.decode(&body, MAX_MESSAGE_BYTES).await?;
    }
    Ok(body)
}

async fn read_decoded(
    mut decoder: impl AsyncRead + Unpin,
    limit: usize,
) -> Result<Vec<u8>, UpstreamError> {
    let mut output = Vec::new();
    let mut chunk = [0; 16 * 1024];
    loop {
        let read = decoder
            .read(&mut chunk)
            .await
            .map_err(|_| UpstreamError::Transport)?;
        if read == 0 {
            return Ok(output);
        }
        if read > limit - output.len() {
            return Err(UpstreamError::LimitExceeded);
        }
        output.extend_from_slice(&chunk[..read]);
        tokio::task::yield_now().await;
    }
}

#[cfg(test)]
mod tests {
    use async_compression::tokio::write::GzipEncoder;
    use tokio::io::AsyncWriteExt;

    use super::*;

    #[tokio::test]
    async fn decoded_body_obeys_its_own_limit() {
        let input = [b'a'; 64];
        let mut encoder = GzipEncoder::new(Vec::new());
        encoder.write_all(&input).await.unwrap();
        encoder.shutdown().await.unwrap();
        let compressed = encoder.into_inner();
        assert_eq!(
            Coding::Gzip.decode(&compressed, input.len()).await.unwrap(),
            input,
        );
        assert!(matches!(
            Coding::Gzip.decode(&compressed, input.len() - 1).await,
            Err(UpstreamError::LimitExceeded)
        ));
    }
}
