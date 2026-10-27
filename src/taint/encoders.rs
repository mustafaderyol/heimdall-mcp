use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};

pub struct SecretEncoder;

impl SecretEncoder {
    /// Produces 3-byte Base64 quantum alignment shifted invariant cores (Offset 0, 1, 2)
    /// for both Standard and URL-Safe Base64 engines.
    pub fn push_base64_aligned_variants(secret: &[u8], out: &mut Vec<Vec<u8>>) {
        if secret.len() < 8 {
            return;
        }

        for engine in [&STANDARD, &URL_SAFE_NO_PAD] {
            // Offset 0: direct encoding of 3-byte chunks (4 characters per chunk)
            let enc0 = engine.encode(secret);
            let valid_len0 = (secret.len() / 3) * 4;
            if valid_len0 >= 8 && valid_len0 <= enc0.len() {
                out.push(enc0.as_bytes()[0..valid_len0].to_vec());
            }

            // Offset 1: 1 byte prefix (0x00). First 2 characters contain dirty prefix bits.
            let mut buf1 = Vec::with_capacity(secret.len() + 1);
            buf1.push(0u8);
            buf1.extend_from_slice(secret);
            let enc1 = engine.encode(&buf1);
            let valid_len1 = (buf1.len() / 3) * 4;
            if valid_len1 > 10 && valid_len1 <= enc1.len() {
                out.push(enc1.as_bytes()[2..valid_len1].to_vec());
            }

            // Offset 2: 2 bytes prefix (0x00, 0x00). First 3 characters contain dirty prefix bits.
            let mut buf2 = Vec::with_capacity(secret.len() + 2);
            buf2.extend_from_slice(&[0u8, 0u8]);
            buf2.extend_from_slice(secret);
            let enc2 = engine.encode(&buf2);
            let valid_len2 = (buf2.len() / 3) * 4;
            if valid_len2 > 11 && valid_len2 <= enc2.len() {
                out.push(enc2.as_bytes()[3..valid_len2].to_vec());
            }
        }
    }

    /// URL-percent encodes a byte slice
    pub fn url_encode(data: &[u8]) -> Vec<u8> {
        let mut encoded = String::new();
        for &b in data {
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
                encoded.push(b as char);
            } else {
                encoded.push_str(&format!("%{:02X}", b));
            }
        }
        encoded.into_bytes()
    }

    /// Generates all evasion variants (Raw, Hex lower/upper, URL-encoded, Base64 offsets, Subdomains)
    pub fn generate_all_variants(secret_bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut variants = Vec::new();

        // 1. Raw secret
        if secret_bytes.len() >= 8 {
            variants.push(secret_bytes.to_vec());
        }

        // 2. Hex lowercase and uppercase
        if secret_bytes.len() >= 8 {
            let hex_lower = hex::encode(secret_bytes);
            let hex_upper = hex_lower.to_uppercase();
            variants.push(hex_lower.into_bytes());
            variants.push(hex_upper.into_bytes());
        }

        // 3. 3-Byte Base64 Quantum Alignment shifted cores
        Self::push_base64_aligned_variants(secret_bytes, &mut variants);

        // 4. URL percent encoding
        let url_enc = Self::url_encode(secret_bytes);
        if url_enc.len() >= 8 && url_enc != secret_bytes {
            variants.push(url_enc);
        }

        // 5. Sliding window for long secrets (>= 32 bytes e.g. private keys, large tokens)
        if secret_bytes.len() >= 32 {
            let mut offset = 0;
            while offset + 24 <= secret_bytes.len() {
                let window = &secret_bytes[offset..offset + 24];
                variants.push(window.to_vec());
                Self::push_base64_aligned_variants(window, &mut variants);
                offset += 8;
            }
        }

        // 6. Subdomain format (e.g. secret.attacker.com where dots or dashes split chunks)
        if secret_bytes.len() >= 16 {
            let chunked_dots = secret_bytes
                .chunks(8)
                .map(|c| String::from_utf8_lossy(c).to_string())
                .collect::<Vec<_>>()
                .join(".");
            variants.push(chunked_dots.into_bytes());
        }

        variants
    }
}
