// SPDX-License-Identifier: Apache-2.0

use std::{borrow::Cow, str::Utf8Error};

use encoding_rs::{Encoding, UTF_8, UTF_16BE, UTF_16LE};
use serde_json::Value;

use super::diagnostics;

pub(super) fn decode_text<'a>(body: &'a [u8], content_type: Option<&str>) -> Cow<'a, str> {
    let content_type = content_type.and_then(|header| header.parse::<mime_guess::Mime>().ok());
    let charset = content_type
        .as_ref()
        .and_then(|mime| mime.get_param("charset"))
        .map(|charset| charset.as_str().to_ascii_lowercase());
    match charset.as_deref().unwrap_or("utf-8") {
        "utf-8-sig" => UTF_8.decode_with_bom_removal(body).0,
        "utf-16" | "utf16" => {
            let (encoding, bytes) = match body {
                [0xfe, 0xff, bytes @ ..] => (UTF_16BE, bytes),
                [0xff, 0xfe, bytes @ ..] => (UTF_16LE, bytes),
                _ => (UTF_16LE, body),
            };
            encoding.decode_without_bom_handling(bytes).0
        }
        "utf-32" | "utf32" => {
            let (little_endian, bytes) = match body {
                [0, 0, 0xfe, 0xff, bytes @ ..] => (false, bytes),
                [0xff, 0xfe, 0, 0, bytes @ ..] => (true, bytes),
                _ => (true, body),
            };
            utf32_text(bytes, little_endian)
        }
        "utf-32be" => utf32_text(body, false),
        "utf-32le" => utf32_text(body, true),
        "iso-8859-1" | "iso8859-1" | "latin-1" | "latin1" | "iso8859_1" => body
            .iter()
            .copied()
            .map(char::from)
            .collect::<String>()
            .into(),
        "ascii" | "us-ascii" => body
            .iter()
            .copied()
            .map(|byte| {
                if byte.is_ascii() {
                    char::from(byte)
                } else {
                    char::REPLACEMENT_CHARACTER
                }
            })
            .collect::<String>()
            .into(),
        label => {
            Encoding::for_label_no_replacement(label.as_bytes())
                .unwrap_or(UTF_8)
                .decode_without_bom_handling(body)
                .0
        }
    }
}

pub(super) fn decode_json(body: &[u8]) -> Result<Value, String> {
    let text: Cow<'_, str> = match body {
        [0, 0, 0xfe, 0xff, ..] => utf32_json(body, false, 4)?,
        [0xff, 0xfe, 0, 0, ..] => utf32_json(body, true, 4)?,
        [0xfe, 0xff, ..] => utf16_json(body, UTF_16BE, 2)?,
        [0xff, 0xfe, ..] => utf16_json(body, UTF_16LE, 2)?,
        [0xef, 0xbb, 0xbf, rest @ ..] => utf8_json(rest)?,
        [0, 0, _, _, ..] => utf32_json(body, false, 0)?,
        [0, _, _, _, ..] | [0, _] => utf16_json(body, UTF_16BE, 0)?,
        [_, 0, 0, 0, ..] => utf32_json(body, true, 0)?,
        [_, 0, _, _, ..] | [_, 0] => utf16_json(body, UTF_16LE, 0)?,
        _ => utf8_json(body)?,
    };
    serde_json::from_str(&text).map_err(|error| diagnostics::syntax_error(&error, &text))
}

fn utf32_units(bytes: &[u8], little_endian: bool) -> impl Iterator<Item = Option<u32>> {
    bytes.chunks(4).map(move |chunk| {
        let bytes = chunk.try_into().ok()?;
        Some(if little_endian {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        })
    })
}

fn utf32_text(bytes: &[u8], little_endian: bool) -> Cow<'_, str> {
    utf32_units(bytes, little_endian)
        .map(|value| {
            value
                .and_then(char::from_u32)
                .unwrap_or(char::REPLACEMENT_CHARACTER)
        })
        .collect::<String>()
        .into()
}

fn utf32_json(bytes: &[u8], little_endian: bool, bom: usize) -> Result<Cow<'_, str>, String> {
    let encoding = if little_endian {
        "utf-32-le"
    } else {
        "utf-32-be"
    };
    let mut text = String::new();
    let mut surrogate = None;
    for (index, unit) in utf32_units(&bytes[bom..], little_endian).enumerate() {
        let offset = bom + index * 4;
        match unit {
            None => {
                return Err(encoding_error(
                    encoding,
                    bytes,
                    offset,
                    bytes.len() - offset,
                    "truncated data",
                ));
            }
            Some(0xd800..=0xdfff) => {
                surrogate.get_or_insert(offset);
                text.push(char::REPLACEMENT_CHARACTER);
            }
            Some(code) => {
                let character = char::from_u32(code).ok_or_else(|| {
                    encoding_error(
                        encoding,
                        bytes,
                        offset,
                        4,
                        "code point not in range(0x110000)",
                    )
                })?;
                text.push(character);
            }
        }
    }
    if let Some(offset) = surrogate {
        let reason = encoding_error(encoding, bytes, offset, 4, "surrogates not allowed");
        return Err(surrogate_error(&text, reason));
    }
    Ok(Cow::Owned(text))
}

fn utf16_json<'a>(
    bytes: &'a [u8],
    encoding: &'static Encoding,
    bom: usize,
) -> Result<Cow<'a, str>, String> {
    let payload = &bytes[bom..];
    if let Some(text) = encoding.decode_without_bom_handling_and_without_replacement(payload) {
        return Ok(text);
    }
    let name = if encoding == UTF_16LE {
        "utf-16-le"
    } else {
        "utf-16-be"
    };
    let (units, remainder) = payload.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(encoding_error(
            name,
            bytes,
            bytes.len() - 1,
            1,
            "truncated data",
        ));
    }
    let units = units.iter().copied().map(|bytes| {
        if encoding == UTF_16LE {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        }
    });
    let mut offset = bom;
    let mut invalid = None;
    for character in char::decode_utf16(units) {
        match character {
            Ok(character) => offset += character.len_utf16() * 2,
            Err(_) => {
                invalid = Some(offset);
                break;
            }
        }
    }
    let reason = invalid.map_or_else(
        || "Invalid UTF-16 encoding".into(),
        |offset| encoding_error(name, bytes, offset, 2, "surrogates not allowed"),
    );
    let (text, _) = encoding.decode_without_bom_handling(payload);
    Err(surrogate_error(&text, reason))
}

fn surrogate_error(text: &str, reason: String) -> String {
    match serde_json::from_str::<Value>(text) {
        Ok(_) => reason,
        Err(error) => diagnostics::syntax_error(&error, text),
    }
}

fn utf8_json(bytes: &[u8]) -> Result<Cow<'_, str>, String> {
    std::str::from_utf8(bytes)
        .map(Cow::Borrowed)
        .map_err(|error| utf8_error(bytes, error))
}

fn utf8_error(bytes: &[u8], error: Utf8Error) -> String {
    let offset = error.valid_up_to();
    let first = bytes[offset];
    let (length, reason) = match error.error_len() {
        None => (bytes.len() - offset, "unexpected end of data"),
        Some(length) if (0xc2..=0xf4).contains(&first) => (length, "invalid continuation byte"),
        Some(length) => (length, "invalid start byte"),
    };
    encoding_error("utf-8", bytes, offset, length, reason)
}

fn encoding_error(
    encoding: &str,
    bytes: &[u8],
    offset: usize,
    length: usize,
    reason: &str,
) -> String {
    let description = if length == 1 {
        format!("byte {:#04x} in position {offset}", bytes[offset])
    } else {
        format!("bytes in position {offset}-{}", offset + length - 1)
    };
    format!("'{encoding}' codec can't decode {description}: {reason}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sniffs_json_encoding_and_uses_declared_charset_for_text_fallback() {
        let mut utf16 = vec![0xff, 0xfe];
        utf16.extend(r#"{"text":"café"}"#.encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(decode_json(&utf16).unwrap(), json!({"text":"café"}));
        let utf32: Vec<_> = r#"{"text":"café"}"#.chars().flat_map(|character| (character as u32).to_be_bytes()).collect();
        assert_eq!(decode_json(&utf32).unwrap(), json!({"text":"café"}));
        let latin1 = b"caf\xe9";
        assert_eq!(
            decode_text(latin1, Some("text/plain; charset=\"iso-8859-1\"")),
            "café",
        );
        assert_eq!(
            decode_json(latin1).unwrap_err(),
            "'utf-8' codec can't decode byte 0xe9 in position 3: unexpected end of data",
        );
    }
}
