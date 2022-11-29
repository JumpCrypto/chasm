//! TODO: Unify GetKey, GenerateKey, UnwrapKey in a single response type
//!
//! Needs adjustments on the protobuf side of things.

// TODO: think about what to leak about this type,
// and how to keep it general for all threshold signing algorithms.

use super::{Re, RequestId};//, request::KeyMeta};
use crate::base64_serde as b64;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum Response {
    GetKey(GetKey),
    DeriveChildKey(DeriveChildKey),
    GenerateKey(GenerateKey),
    ListKeys(ListKeys),
    UnwrapKey(UnwrapKey),
    Precompute(Precompute),
    Sign(Sign),
    FailedRequest(FailedRequest),
    Heartbeat(Heartbeat),
}

// /// The (successful) response to a request::{GenerateKey, GetKey, UnwrapKey}
// #[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize)]
// pub struct KeyInfo {
//     // /// Chasm node's address
//     // pub responder: AccountId,
//     /// Request metadata
//     pub re: Re,
//     /// Serialized public key of the generated key
//     #[serde(with = "Base64")]
//     pub public_key: Vec<u8>,
// }

// pub type GenerateKey = KeyInfo;
// pub type GetKey = KeyInfo;
// pub type UnwrapKey = KeyInfo;

// The (successful) response to a request::DeriveChildKey
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
pub struct DeriveChildKey {
    // /// Chasm node's address
    // pub responder: AccountId,
    /// Request metadata
    pub re: Re,
    /// Serialized public key of the generated key
    // #[schemars(with = "Base64")]
    #[serde(serialize_with = "b64::serialize", deserialize_with = "b64::deserialize")]
    pub public_key: Vec<u8>,
}

/// The (successful) response to a request::GenerateKey
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
pub struct GenerateKey {
    // /// Chasm node's address
    // pub responder: AccountId,
    /// Request metadata
    pub re: Re,
    /// Serialized public key of the generated key
    #[serde(serialize_with = "b64::serialize", deserialize_with = "b64::deserialize")]
    pub public_key: Vec<u8>,
}

/// The (successful) response to a request::GenerateKey
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
pub struct GetKey {
    /// Request metadata
    pub re: Re,
    // pub meta: KeyMeta,
    /// Serialized public key of the generated key
    #[serde(serialize_with = "b64::serialize", deserialize_with = "b64::deserialize")]
    pub public_key: Vec<u8>,
}

/// The (successful) response to a request::UnwrapKey
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
pub struct UnwrapKey {
    // /// Chasm node's address
    // pub responder: AccountId,
    /// Request metadata
    pub re: Re,
    /// Serialized public key of the unwrapped key
    #[serde(serialize_with = "b64::serialize", deserialize_with = "b64::deserialize")]
    pub public_key: Vec<u8>,
}

/// The (successful) response to a request::ListKeys
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
pub struct ListKeys {
    // /// Chasm node's address
    // pub responder: AccountId,
    /// Request metadata
    pub re: Re,
    pub names: Vec<String>,
}

use std::collections::BTreeMap as Map;
type Participant = std::num::NonZeroU32;

fn serialize_vec_map<S>(map: &Map<Participant, Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
where S: serde::Serializer
{
    let transform: Map<Participant, String> = map.iter()
        .map(|(&participant, vec)| (participant, base64::encode(&vec)))
        .collect();
    use serde::Serialize;
    transform.serialize(serializer)
}

/// The (successful) response to a request::Precompute
// #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Precompute {
    // /// Chasm node's address
    // pub responder: AccountId,
    /// Request metadata
    pub re: Re,
    /// TODO: Have the points in this serialize as Base64,
    /// also don't need the threshold and UUID
    #[serde(serialize_with = "serialize_vec_map")]
    pub commitments: Map<Participant, Vec<u8>>,
    // #[serde(serialize_with = "serialize_map_of_points")]
    // pub hidings: Map<Participant, Vec<Point>>,
}

/// The (successful) response to a request::Sign
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
pub struct Sign {
    // /// Chasm node's address
    // pub responder: AccountId,
    /// Request metadata
    pub re: Re,
    /// Serialized signature
    #[serde(serialize_with = "b64::serialize", deserialize_with = "b64::deserialize")]
    pub signature: Vec<u8>,
}

/// The response to a failed request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
pub struct FailedRequest {
    /// Request metadata
    pub re: Re,
    pub error: crate::crypto::Error,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
pub struct Heartbeat {
    /// Request metadata
    pub re: Re,
}

impl GetKey {
    pub fn with(request: &RequestId, public_key: &[u8]) -> Self {
        Self {
            re: Re::with(request),
            public_key: public_key.to_vec(),
        }
    }
}

impl DeriveChildKey {
    pub fn with(request: &RequestId, public_key: &[u8]) -> Self {
        Self {
            re: Re::with(request),
            public_key: public_key.to_vec(),
        }
    }
}

impl GenerateKey {
    pub fn with(request: &RequestId, public_key: &[u8]) -> Self {
        Self {
            re: Re::with(request),
            public_key: public_key.to_vec(),
        }
    }
}

impl UnwrapKey {
    pub fn with(request: &RequestId, public_key: &[u8]) -> Self {
        Self {
            re: Re::with(request),
            public_key: public_key.to_vec(),
        }
    }
}

impl Precompute {
    pub fn with(request: &RequestId, commitments: &Map<Participant, Vec<u8>>) -> Self {
        Self {
            re: Re::with(request),
            commitments: commitments.clone()
        }
    }
}

impl Sign {
    pub fn with(request: &RequestId, signature: &[u8]) -> Self {
        Self {
            re: Re::with(request),
            signature: signature.to_vec(),
        }
    }
}

impl ListKeys {
    pub fn with(request: &RequestId, names: &[String]) -> Self {
        Self {
            re: Re::with(request),
            names: names.to_owned(),
        }
    }
}

impl FailedRequest {
    pub fn with(request: &str, error: crate::crypto::Error) -> Self {
        Self {
            re: Re::with(request),
            error,
        }
    }
}

impl From<GetKey> for Response {
    fn from(response: GetKey) -> Response {
        Response::GetKey(response)
    }
}

impl From<DeriveChildKey> for Response {
    fn from(response: DeriveChildKey) -> Response {
        Response::DeriveChildKey(response)
    }
}

impl From<GenerateKey> for Response {
    fn from(response: GenerateKey) -> Response {
        Response::GenerateKey(response)
    }
}

impl From<UnwrapKey> for Response {
    fn from(response: UnwrapKey) -> Response {
        Response::UnwrapKey(response)
    }
}

impl From<Precompute> for Response {
    fn from(response: Precompute) -> Response {
        Response::Precompute(response)
    }
}

impl From<Sign> for Response {
    fn from(response: Sign) -> Response {
        Response::Sign(response)
    }
}

impl From<ListKeys> for Response {
    fn from(response: ListKeys) -> Response {
        Response::ListKeys(response)
    }
}

