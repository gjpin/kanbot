//! Unpadded base64url (RFC 4648, section 5), for tests and dev tools.

/// Encodes `bytes` as unpadded base64url.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
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
            if let Some(&c) = usize::try_from(index).ok().and_then(|i| ALPHABET.get(i)) {
                out.push(char::from(c));
            }
        }
    }
    out
}
