// Copyright 2026 WritersLogic. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license,
// at your option.

//! Standard Base64 (RFC 4648 §4, with padding), hand-rolled to keep the crate
//! dependency-free.
//!
//! The decoder is strict: the standard alphabet only, correct padding, and no
//! interior whitespace. The specification directs a validator to strip *leading
//! and trailing* whitespace from the `script` content and decode what remains,
//! so interior whitespace is not something a conformant encoder emits. Being
//! strict here means this crate never accepts a document another validator
//! would reject.

const ENCODE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode `bytes` as standard Base64 with padding, on a single line.
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(ENCODE[(n >> 18) as usize & 63] as char);
        out.push(ENCODE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ENCODE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ENCODE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn sextet(b: u8) -> Option<u32> {
    Some(match b {
        b'A'..=b'Z' => (b - b'A') as u32,
        b'a'..=b'z' => (b - b'a') as u32 + 26,
        b'0'..=b'9' => (b - b'0') as u32 + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    })
}

/// Decode standard Base64 with padding. Returns `None` on any character outside
/// the alphabet, a length that is not a multiple of four, misplaced padding, or
/// non-zero bits in a padded tail.
pub(crate) fn decode(text: &[u8]) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut chunks = text.chunks_exact(4).peekable();
    while let Some(chunk) = chunks.next() {
        let last = chunks.peek().is_none();
        // Padding is only ever legal in the final quantum.
        let pad = chunk.iter().filter(|&&b| b == b'=').count();
        if pad > 0 && (!last || pad > 2 || chunk[..4 - pad].contains(&b'=')) {
            return None;
        }
        let mut n = 0u32;
        for &b in &chunk[..4 - pad] {
            n = (n << 6) | sextet(b)?;
        }
        // The padded bits must be zero, so one encoding maps to one byte string.
        n <<= 6 * pad;
        let bytes = n.to_be_bytes();
        out.extend_from_slice(&bytes[1..4 - pad]);
        if pad > 0 && bytes[4 - pad..].iter().any(|&b| b != 0) {
            return None;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 §10.
    const VECTORS: [(&[u8], &str); 7] = [
        (b"", ""),
        (b"f", "Zg=="),
        (b"fo", "Zm8="),
        (b"foo", "Zm9v"),
        (b"foob", "Zm9vYg=="),
        (b"fooba", "Zm9vYmE="),
        (b"foobar", "Zm9vYmFy"),
    ];

    #[test]
    fn encode_matches_rfc4648_vectors() {
        for (raw, encoded) in VECTORS {
            assert_eq!(encode(raw), encoded, "encoding {raw:?}");
        }
    }

    #[test]
    fn decode_matches_rfc4648_vectors() {
        for (raw, encoded) in VECTORS {
            assert_eq!(
                decode(encoded.as_bytes()).as_deref(),
                Some(raw),
                "{encoded}"
            );
        }
    }

    #[test]
    fn round_trips_every_byte_value() {
        let all: Vec<u8> = (0..=255).collect();
        for len in 0..=all.len() {
            let slice = &all[..len];
            assert_eq!(decode(encode(slice).as_bytes()).as_deref(), Some(slice));
        }
    }

    #[test]
    fn rejects_bad_length_and_alphabet() {
        assert_eq!(decode(b"Zm9vY"), None, "length not a multiple of four");
        assert_eq!(decode(b"Zm9-"), None, "URL-safe alphabet is not accepted");
        assert_eq!(decode(b"Zm9_"), None, "URL-safe alphabet is not accepted");
        assert_eq!(decode(b"Zm9*"), None, "character outside the alphabet");
    }

    #[test]
    fn rejects_interior_whitespace() {
        // A validator strips only leading and trailing whitespace, so an encoder
        // that wraps lines produces something no conformant validator decodes.
        assert_eq!(decode(b"Zm9v\nYmFy"), None);
        assert_eq!(decode(b"Zm9v YmFy"), None);
    }

    #[test]
    fn rejects_misplaced_padding() {
        assert_eq!(decode(b"Z=9v"), None, "padding inside a quantum");
        assert_eq!(
            decode(b"Zg==Zg=="),
            None,
            "padding before the final quantum"
        );
        assert_eq!(decode(b"===="), None, "four padding characters");
        assert_eq!(decode(b"Z==="), None, "three padding characters");
    }

    #[test]
    fn rejects_non_canonical_tails() {
        // "Zh==" would decode to the same byte as "Zg==" but sets discarded bits,
        // so accepting it would make the encoding non-injective.
        assert_eq!(decode(b"Zg=="), Some(vec![b'f']));
        assert_eq!(decode(b"Zh=="), None);
        assert_eq!(decode(b"Zm9="), None);
    }
}
