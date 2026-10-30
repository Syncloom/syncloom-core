//! serde helper: `Vec<u8>` as URL-safe unpadded base64 strings in JSON.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use serde::{Deserialize, Deserializer, Serializer};

pub fn encode(b: &[u8]) -> String {
    B64.encode(b)
}
pub fn decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    B64.decode(s.trim_end_matches('='))
}
pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&encode(v))
}
pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(d)?;
    decode(&s).map_err(serde::de::Error::custom)
}
