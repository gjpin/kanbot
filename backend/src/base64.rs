//! Base64 (RFC 4648): unpadded base64url for the tokens kanbot issues and
//! reads (JWT segments), and decoding of standard base64 for the keys it is
//! given.

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// `bytes` as unpadded base64url (RFC 4648, section 5).
#[must_use]
pub fn encode_url(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));
    for chunk in bytes.chunks(3) {
        let byte = |i: usize| chunk.get(i).copied().unwrap_or(0);
        let n = u32::from_be_bytes([0, byte(0), byte(1), byte(2)]);
        let chars = match chunk.len() {
            1 => 2,
            2 => 3,
            _ => 4,
        };
        for shift in [18_u32, 12, 6, 0].into_iter().take(chars) {
            let index = n.checked_shr(shift).unwrap_or(0) & 0x3f;
            if let Some(&c) = usize::try_from(index)
                .ok()
                .and_then(|index| URL_SAFE.get(index))
            {
                out.push(char::from(c));
            }
        }
    }
    out
}

/// Decodes standard base64 (RFC 4648, section 4), padded or not. `None`
/// for any other character, a misplaced `=`, an impossible length, or
/// non-zero bits after the last byte (so each input has one meaning).
#[must_use]
pub fn decode_standard(text: &str) -> Option<Vec<u8>> {
    let unpadded = text.trim_end_matches('=');
    let padding = text.len().checked_sub(unpadded.len())?;
    if padding > 2 || (padding > 0 && !text.len().is_multiple_of(4)) {
        return None;
    }
    decode(unpadded, STANDARD)
}

/// Decodes unpadded base64url (RFC 4648, section 5), as in JWTs. `None` for
/// any other character (`+`, `/` and `=` included), an impossible length,
/// or non-zero bits after the last byte.
#[must_use]
pub fn decode_url(text: &str) -> Option<Vec<u8>> {
    decode(text, URL_SAFE)
}

fn decode(unpadded: &str, alphabet: &[u8; 64]) -> Option<Vec<u8>> {
    let values = unpadded
        .bytes()
        .map(|c| {
            alphabet
                .iter()
                .position(|&s| s == c)
                .and_then(|value| u32::try_from(value).ok())
        })
        .collect::<Option<Vec<u32>>>()?;
    let mut out = Vec::with_capacity(values.len().saturating_mul(3) / 4);
    for chunk in values.chunks(4) {
        let n = chunk
            .iter()
            .chain(std::iter::repeat(&0))
            .take(4)
            .try_fold(0_u32, |n, value| n.checked_mul(64)?.checked_add(*value))?;
        let [_, a, b, c] = n.to_be_bytes();
        let (bytes, unused_bits): (&[u8], u32) = match chunk.len() {
            4 => (&[a, b, c], 0),
            3 => (&[a, b], c.into()),
            // Two characters carry 12 bits: the last 4 land in `b`.
            2 => (&[a], b.into()),
            _ => return None,
        };
        if unused_bits != 0 {
            return None;
        }
        out.extend_from_slice(bytes);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn encodes_the_rfc_4648_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode_url(input.as_bytes()), expected);
        }
        assert_eq!(encode_url(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn decodes_the_rfc_4648_vectors() {
        for (expected, input) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
            ("f", "Zg"),
            ("fooba", "Zm9vYmE"),
        ] {
            assert_eq!(
                decode_standard(input).unwrap(),
                expected.as_bytes(),
                "{input}"
            );
        }
        assert_eq!(decode_standard("+/8=").unwrap(), [0xfb, 0xff]);
    }

    #[test]
    fn refuses_anything_else() {
        for input in [
            "Z",
            "Zg===",
            "Zg=",
            "Z=g=",
            "-_8=",
            "Zm9v Yg==",
            "Zh==",
            "Zm9=",
            "Zm9vY",
            "=",
        ] {
            assert_eq!(decode_standard(input), None, "{input}");
        }
    }

    #[test]
    fn decodes_base64url_strictly() {
        assert_eq!(decode_url("-_8").unwrap(), [0xfb, 0xff]);
        assert_eq!(decode_url("Zm9vYmE").unwrap(), b"fooba");
        for input in ["+/8", "Zg==", "Zg=", "Z", "Zh", "Zm9 v"] {
            assert_eq!(decode_url(input), None, "{input}");
        }
    }

    fn to_standard(url: &str) -> String {
        url.replace('-', "+").replace('_', "/")
    }

    proptest! {
        #[test]
        fn decoding_reverses_encoding(bytes in prop::collection::vec(any::<u8>(), 0..100)) {
            let encoded = to_standard(&encode_url(&bytes));
            prop_assert_eq!(decode_standard(&encoded).unwrap(), bytes.clone());
            let padding = "=".repeat(encoded.len().next_multiple_of(4).checked_sub(encoded.len()).unwrap());
            prop_assert_eq!(decode_standard(&format!("{encoded}{padding}")).unwrap(), bytes);
        }

        #[test]
        fn base64url_decoding_reverses_encoding(bytes in prop::collection::vec(any::<u8>(), 0..100)) {
            prop_assert_eq!(decode_url(&encode_url(&bytes)).unwrap(), bytes);
        }

        #[test]
        fn decoding_never_panics(text in "\\PC*") {
            let _ = decode_standard(&text);
            let _ = decode_url(&text);
        }
    }
}
