use std::time::SystemTime;

pub mod request;
pub mod response;

pub use std::num::NonZeroU32;
pub type RequestId = String;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
pub struct Re {
	/// Request we're responding to
	pub name: RequestId,
	/// Unix Time we're sending the response
	pub at: i64,
}

impl Re {
    pub fn with(name: &str) -> Self {
        Self { name: name.to_string(), at: crate::now() }
    }
}

impl Default for Re {
    fn default() -> Self {
        Self {
            name: "".to_string(),
            at: crate::now(),
        }
    }
}

pub type Error = crate::crypto::Error;
pub type Result<T> = std::result::Result<T, Error>;

pub trait Id {
    fn id(&self) -> RequestId;
}

/// Short summary useful for logs
pub trait Short {
    fn short(&self) -> String;
}

pub mod at_serde {
    use std::time::Duration;
    use serde::{Deserializer, Serializer};
    use super::SystemTime;

    fn encode_duration_microseconds<S>(duration: &Duration, serializer: S)
        -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        use serde::ser::{Error, Serialize};
        duration.as_secs().checked_mul(1_000_000).and_then(|x| {
            x.checked_add(duration.subsec_micros() as u64)
        })
        .ok_or_else(|| S::Error::custom("duration value out of range"))
        .and_then(|v| v.serialize(serializer))
    }

    pub fn serialize<S>(time: &SystemTime, serializer: S)
        -> Result<S::Ok, S::Error>
    where
        S: Serializer
    {
        use serde::ser::Error;
        time.duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| S::Error::custom("invalid system time"))
            .and_then(|x| encode_duration_microseconds(&x, serializer))
    }

    pub fn deserialize<'de, D>(deserializer: D)
        -> Result<SystemTime, D::Error>
    where
        D: Deserializer<'de>
    {
        use serde::de::{Deserialize, Error};
        let microseconds: u64 = Deserialize::deserialize(deserializer)?;
        let duration = Duration::from_micros(microseconds);
        SystemTime::UNIX_EPOCH
            .checked_add(duration)
            .ok_or_else(|| D::Error::custom("invalid system time"))
    }


}

