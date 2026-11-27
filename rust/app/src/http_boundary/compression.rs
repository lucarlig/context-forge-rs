// SPDX-License-Identifier: Apache-2.0

use std::{error::Error, io};

use async_compression::{
    Level,
    tokio::write::{BrotliEncoder, GzipEncoder, ZstdEncoder},
};
use axum::{
    body::{Body, Bytes, to_bytes},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use futures_util::stream;
use http_body::{Body as _, Frame};
use http_body_util::{BodyExt, StreamBody};
use percent_encoding::percent_decode_str;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::response_policy::add_vary;
use crate::config::{flag, parse};

pub(super) struct Compression {
    minimum_size: u64,
    gzip_level: Level,
    brotli_quality: Level,
    zstd_level: Level,
    json_mcp: bool,
}

impl Compression {
    pub(super) fn from_env() -> Result<Option<Self>, Box<dyn Error + Send + Sync>> {
        if !flag("COMPRESSION_ENABLED")?.unwrap_or(true) {
            return Ok(None);
        }
        let level = |name, default, bounds: std::ops::RangeInclusive<i32>| {
            let value = parse(name, default)?;
            if !bounds.contains(&value) {
                return Err::<Level, Box<dyn Error + Send + Sync>>(
                    format!("invalid {name}").into(),
                );
            }
            Ok(Level::Precise(value))
        };
        Ok(Some(Self {
            minimum_size: parse("COMPRESSION_MINIMUM_SIZE", 500)?,
            gzip_level: level("COMPRESSION_GZIP_LEVEL", 6, 1..=9)?,
            brotli_quality: level("COMPRESSION_BROTLI_QUALITY", 4, 0..=11)?,
            zstd_level: level("COMPRESSION_ZSTD_LEVEL", 3, 1..=22)?,
            json_mcp: flag("JSON_RESPONSE_ENABLED")?.unwrap_or(true),
        }))
    }

    pub(super) fn supports_path(&self, path: &str) -> bool {
        if self.json_mcp {
            return true;
        }
        let path = percent_decode_str(path).decode_utf8_lossy();
        !path.ends_with("/mcp") && !path.ends_with("/mcp/")
    }

    pub(super) async fn apply(&self, mut response: Response, coding: Option<Coding>) -> Response {
        let Some(event_stream) = eligible(&response) else {
            return response;
        };
        let length = response.body().size_hint().exact();
        if !event_stream && length.is_some_and(|len| len < self.minimum_size) {
            return response;
        }
        add_vary(response.headers_mut(), "Accept-Encoding");
        let Some(coding) = coding else {
            return response;
        };
        let (mut parts, body) = response.into_parts();
        let length = length
            .and_then(|size| usize::try_from(size).ok())
            .filter(|_| !event_stream && !parts.headers.contains_key(header::TRAILER));
        let encoded = match coding {
            Coding::Zstd => {
                encode(
                    ZstdEncoder::with_quality(Vec::new(), self.zstd_level),
                    body,
                    length,
                    event_stream,
                )
                .await
            }
            Coding::Brotli => {
                encode(
                    BrotliEncoder::with_quality(Vec::new(), self.brotli_quality),
                    body,
                    length,
                    event_stream,
                )
                .await
            }
            Coding::Gzip => {
                encode(
                    GzipEncoder::with_quality(Vec::new(), self.gzip_level),
                    body,
                    length,
                    event_stream,
                )
                .await
            }
        };
        match encoded {
            Ok(output) => {
                parts.headers.insert(
                    header::CONTENT_ENCODING,
                    HeaderValue::from_static(coding.name()),
                );
                if let Some(length) = output.size_hint().exact() {
                    parts
                        .headers
                        .insert(header::CONTENT_LENGTH, HeaderValue::from(length));
                } else {
                    parts.headers.remove(header::CONTENT_LENGTH);
                }
                Response::from_parts(parts, output)
            }
            Err(error) => {
                tracing::error!(%error, coding = coding.name(), "could not compress HTTP response");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Coding {
    Zstd,
    Brotli,
    Gzip,
}

impl Coding {
    const PRIORITY: [Self; 3] = [Self::Zstd, Self::Brotli, Self::Gzip];

    fn name(self) -> &'static str {
        match self {
            Self::Zstd => "zstd",
            Self::Brotli => "br",
            Self::Gzip => "gzip",
        }
    }

    pub(super) fn select(headers: &HeaderMap) -> Option<Self> {
        let mut explicit = [false; 3];
        let mut rejected = [false; 3];
        let mut wildcard = false;
        for value in headers.get_all(header::ACCEPT_ENCODING).iter() {
            let Ok(raw) = value.to_str() else {
                continue;
            };
            for item in raw.split(',') {
                let mut fields = item.split(';');
                let Some(name) = fields.next().map(str::trim) else {
                    continue;
                };
                let accepts = fields
                    .find_map(|parameter| {
                        let (key, value) =
                            parameter.trim().split_once('=').unwrap_or((parameter, ""));
                        key.trim()
                            .eq_ignore_ascii_case("q")
                            .then(|| value.trim().parse::<f64>().is_ok_and(|weight| weight > 0.0))
                    })
                    .unwrap_or(true);
                if name == "*" {
                    wildcard |= accepts;
                    continue;
                }
                if let Some(coding) = Self::PRIORITY
                    .into_iter()
                    .find(|coding| name.eq_ignore_ascii_case(coding.name()))
                {
                    explicit[coding as usize] = accepts;
                    rejected[coding as usize] |= !accepts;
                }
            }
        }
        Self::PRIORITY
            .into_iter()
            .find(|coding| explicit[*coding as usize] || wildcard && !rejected[*coding as usize])
    }
}

fn eligible(response: &Response) -> Option<bool> {
    let status = response.status();
    if status.is_informational()
        || matches!(
            status,
            StatusCode::NO_CONTENT | StatusCode::RESET_CONTENT | StatusCode::NOT_MODIFIED
        )
        || response.headers().contains_key(header::CONTENT_RANGE)
        || response
            .headers()
            .get_all(header::CONTENT_ENCODING)
            .iter()
            .any(|value| {
                value.as_bytes().split(|byte| *byte == b',').any(|coding| {
                    let coding = coding.trim_ascii();
                    !coding.is_empty() && !coding.eq_ignore_ascii_case(b"identity")
                })
            })
    {
        return None;
    }
    let content_type = response
        .headers()
        .get_all(header::CONTENT_TYPE)
        .iter()
        .next_back()?;
    let media_type = content_type.to_str().ok()?.split(';').next()?.trim();
    if media_type.eq_ignore_ascii_case("text/event-stream") {
        return Some(true);
    }
    COMPRESSIBLE
        .iter()
        .any(|allowed| media_type.eq_ignore_ascii_case(allowed))
        .then_some(false)
}

const COMPRESSIBLE: &[&str] = &[
    "application/atom+xml",
    "application/connect+json",
    "application/connect+proto",
    "application/eot",
    "application/font-sfnt",
    "application/font-woff",
    "application/font",
    "application/geo+json",
    "application/gpx+xml",
    "application/graphql+json",
    "application/javascript-binast",
    "application/javascript",
    "application/json",
    "application/ld+json",
    "application/manifest+json",
    "application/opentype",
    "application/otf",
    "application/proto",
    "application/protobuf",
    "application/rdf+xml",
    "application/rss+xml",
    "application/truetype",
    "application/ttf",
    "application/vnd.api+json",
    "application/vnd.google.protobuf",
    "application/vnd.mapbox-vector-tile",
    "application/vnd.ms-fontobject",
    "application/wasm",
    "application/x-google-protobuf",
    "application/x-httpd-cgi",
    "application/x-javascript",
    "application/x-opentype",
    "application/x-otf",
    "application/x-perl",
    "application/x-protobuf",
    "application/x-ttf",
    "application/x-web-app-manifest+json",
    "application/xhtml+xml",
    "application/xml",
    "font/eot",
    "font/otf",
    "font/ttf",
    "font/x-woff",
    "image/bmp",
    "image/svg+xml",
    "image/vnd.microsoft.icon",
    "image/x-icon",
    "multipart/bag",
    "multipart/mixed",
    "text/cache-manifest",
    "text/calendar",
    "text/css",
    "text/html",
    "text/javascript",
    "text/js",
    "text/markdown",
    "text/plain",
    "text/richtext",
    "text/vcard",
    "text/vnd.rim.location.xloc",
    "text/vtt",
    "text/x-component",
    "text/x-cross-domain-policy",
    "text/x-java-source",
    "text/x-markdown",
    "text/x-script",
    "text/xml",
];

trait Encoder: AsyncWrite + Send + Unpin + 'static {
    fn output(&mut self) -> Vec<u8>;
}

macro_rules! encoder {
    ($($ty:ident),+ $(,)?) => {$(
        impl Encoder for $ty<Vec<u8>> {
            fn output(&mut self) -> Vec<u8> {
                std::mem::take(self.get_mut())
            }
        }
    )+};
}

encoder!(ZstdEncoder, BrotliEncoder, GzipEncoder);

async fn encode<E: Encoder>(
    mut encoder: E,
    body: Body,
    length: Option<usize>,
    flush: bool,
) -> io::Result<Body> {
    if let Some(length) = length {
        let bytes = to_bytes(body, length).await.map_err(io::Error::other)?;
        encoder.write_all(&bytes).await?;
        encoder.shutdown().await?;
        return Ok(Body::from(encoder.output()));
    }
    let frames = stream::try_unfold(
        (body, Some(encoder), None),
        move |(mut body, encoder, trailers)| async move {
            if let Some(trailers) = trailers {
                return Ok(Some((trailers, (body, None, None))));
            }
            let Some(mut encoder) = encoder else {
                return Ok(None);
            };
            loop {
                let terminal = match body.frame().await.transpose().map_err(io::Error::other)? {
                    Some(frame) if frame.is_data() => {
                        let data = frame.into_data().expect("body data frame");
                        if data.is_empty() {
                            continue;
                        }
                        encoder.write_all(&data).await?;
                        if flush {
                            encoder.flush().await?;
                        }
                        let encoded = encoder.output();
                        if !encoded.is_empty() {
                            return Ok(Some((
                                Frame::data(Bytes::from(encoded)),
                                (body, Some(encoder), None),
                            )));
                        }
                        continue;
                    }
                    terminal => terminal,
                };
                encoder.shutdown().await?;
                let encoded = encoder.output();
                return Ok::<_, io::Error>(if encoded.is_empty() {
                    terminal.map(|trailers| (trailers, (body, None, None)))
                } else {
                    Some((Frame::data(Bytes::from(encoded)), (body, None, terminal)))
                });
            }
        },
    );
    Ok(Body::new(StreamBody::new(frames)))
}

#[cfg(test)]
mod tests {
    use async_compression::tokio::bufread::GzipDecoder;
    use tokio::io::AsyncReadExt;

    use super::*;

    #[tokio::test]
    async fn preserves_streamed_response_trailers() {
        let trailers = HeaderMap::from_iter([(
            header::HeaderName::from_static("x-fixture-trailer"),
            HeaderValue::from_static("finished"),
        )]);
        let frames = [
            Ok::<_, io::Error>(Frame::data(Bytes::from_static(b"hello "))),
            Ok(Frame::data(Bytes::from_static(b"world"))),
            Ok(Frame::trailers(trailers.clone())),
        ];
        let body = Body::new(StreamBody::new(stream::iter(frames)));
        let output = encode(GzipEncoder::new(Vec::new()), body, None, true)
            .await
            .unwrap();
        let collected = output.collect().await.unwrap();
        assert_eq!(collected.trailers(), Some(&trailers));
        let encoded = collected.to_bytes();
        let mut decoder = GzipDecoder::new(encoded.as_ref());
        let mut text = String::new();
        decoder.read_to_string(&mut text).await.unwrap();
        assert_eq!(text, "hello world");
    }

    #[test]
    fn omits_byte_ranges_and_preencoded_responses() {
        let mut response = Response::new(Body::from("hello world"));
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert_eq!(eligible(&response), Some(false));
        response.headers_mut().insert(
            header::CONTENT_ENCODING,
            HeaderValue::from_static("identity, br"),
        );
        assert_eq!(eligible(&response), None);
        response.headers_mut().remove(header::CONTENT_ENCODING);
        response.headers_mut().insert(
            header::CONTENT_RANGE,
            HeaderValue::from_static("bytes 0-10/17"),
        );
        assert_eq!(eligible(&response), None);
    }
}
