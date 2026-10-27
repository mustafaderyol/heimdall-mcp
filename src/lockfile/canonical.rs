use crate::error::{McpLockError, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// RFC 8785 JSON Canonicalization Scheme (JCS) and Strict Duplicate Key Validator
pub struct Canonicalizer;

impl Canonicalizer {
    /// Validates that raw JSON string contains no duplicate keys at any nesting level.
    /// Defends against Parser Differential Attacks (RFC 8785 §3.2.2.2 / I-JSON).
    pub fn validate_no_duplicate_keys(raw_json: &str) -> Result<()> {
        let mut de = serde_json::Deserializer::from_str(raw_json);
        Self::validate_de_no_duplicate_keys(&mut de)?;
        Ok(())
    }

    fn validate_de_no_duplicate_keys<'de, R>(de: &mut serde_json::Deserializer<R>) -> Result<()>
    where
        R: serde_json::de::Read<'de>,
    {
        use serde::de::DeserializeSeed;

        struct StrictVisitor;

        impl<'de> serde::de::Visitor<'de> for StrictVisitor {
            type Value = ();

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("any valid JSON value without duplicate keys")
            }

            fn visit_bool<E>(self, _v: bool) -> std::result::Result<Self::Value, E> {
                Ok(())
            }

            fn visit_i64<E>(self, _v: i64) -> std::result::Result<Self::Value, E> {
                Ok(())
            }

            fn visit_u64<E>(self, _v: u64) -> std::result::Result<Self::Value, E> {
                Ok(())
            }

            fn visit_f64<E>(self, _v: f64) -> std::result::Result<Self::Value, E> {
                Ok(())
            }

            fn visit_str<E>(self, _v: &str) -> std::result::Result<Self::Value, E> {
                Ok(())
            }

            fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
                Ok(())
            }

            fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                deserializer.deserialize_any(StrictVisitor)
            }

            fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
                Ok(())
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                while let Some(()) = seq.next_element_seed(StrictSeed)? {}
                Ok(())
            }

            fn visit_map<M>(self, mut access: M) -> std::result::Result<Self::Value, M::Error>
            where
                M: serde::de::MapAccess<'de>,
            {
                let mut seen_keys = HashSet::new();
                while let Some(key) = access.next_key::<String>()? {
                    if !seen_keys.insert(key.clone()) {
                        return Err(serde::de::Error::custom(format!(
                            "PARSER_DIFFERENTIAL_VIOLATION: Duplicate key '{}' detected in JSON object",
                            key
                        )));
                    }
                    let () = access.next_value_seed(StrictSeed)?;
                }
                Ok(())
            }
        }

        struct StrictSeed;

        impl<'de> DeserializeSeed<'de> for StrictSeed {
            type Value = ();

            fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                deserializer.deserialize_any(StrictVisitor)
            }
        }

        use serde::Deserializer;
        de.deserialize_any(StrictVisitor)
            .map_err(|e| McpLockError::DuplicateKey(e.to_string()))?;
        Ok(())
    }

    /// Serializes a JSON value into deterministic RFC 8785 canonical bytes.
    pub fn canonicalize(val: &Value) -> Result<Vec<u8>> {
        serde_json_canonicalizer::to_vec(val)
            .map_err(|e| McpLockError::Canonicalization(e.to_string()))
    }

    /// Computes deterministic SHA-256 hash of a canonicalized JSON value.
    pub fn canonical_sha256(val: &Value) -> Result<String> {
        let canonical_bytes = Self::canonicalize(val)?;
        let mut hasher = Sha256::new();
        hasher.update(&canonical_bytes);
        Ok(hex::encode(hasher.finalize()))
    }

    /// Parses a raw JSON string with strict duplicate-key defense,
    /// canonicalizes it according to RFC 8785, and computes its SHA-256.
    pub fn parse_and_canonicalize(raw_json: &str) -> Result<(Value, Vec<u8>, String)> {
        Self::validate_no_duplicate_keys(raw_json)?;
        let val: Value = serde_json::from_str(raw_json)?;
        let canonical_bytes = Self::canonicalize(&val)?;
        let mut hasher = Sha256::new();
        hasher.update(&canonical_bytes);
        let digest = hex::encode(hasher.finalize());
        Ok((val, canonical_bytes, digest))
    }
}
