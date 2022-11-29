

#[macro_use]
mod macros;

#[macro_use(Deserialize, Serialize)]
extern crate serde;

pub mod api;
pub mod cosmos;
pub mod crypto;
pub mod error;
pub mod frost;
pub mod proto;
pub mod test_util;

pub use frost::{Participant, Threshold};

pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

pub mod base64_serde {
    use serde::{Serialize, Deserialize};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        let base64 = base64::encode(v);
        String::serialize(&base64, s)
    }
    
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let base64 = String::deserialize(d)?;
        base64::decode(base64.as_bytes())
            .map_err(|e| serde::de::Error::custom(e))
    }
}
