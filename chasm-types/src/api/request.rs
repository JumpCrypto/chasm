use std::num::NonZeroU32;

pub use crate::frost::Participant;

use crate::crypto::{
    Algorithm, PublicKeyFormat, SecretKeyFormat, SignatureFormat,
    Error, Result,
};

use super::{Id, Re, RequestId, Short};


#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
pub enum Request {
    GetKey(GetKey),
    GenerateKey(GenerateKey),
    DeriveChildKey(DeriveChildKey),
    // TODO: revamp KeyMeta to contain the participant indices,
    // then this could just have value KeyMeta
    // GenerateThresholdKey(GenerateThresholdKey),
    UnwrapKey(UnwrapKey),
    ListKeys(ListKeys),
    Precompute(Precompute),
    Sign(Sign),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
pub struct ThresholdMeta {
    // pub cluster: String,
    pub threshold: NonZeroU32,
    pub participants: Vec<NonZeroU32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, Default, schemars::JsonSchema)]
pub struct KeyMeta {
    pub name: String,
    pub algorithm: Algorithm,
    /// If this is None, this is a local key.
    /// If this is Some, this is a cluster key.
    pub threshold: Option<ThresholdMeta>,
    pub format: PublicKeyFormat,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
pub struct ThresholdKeyMeta {
    pub name: String,
    pub algorithm: Algorithm,
    pub threshold: ThresholdMeta,
    pub format: PublicKeyFormat,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, Default, schemars::JsonSchema)]
pub struct GenerateKey {
    pub re: Re,
    pub meta: KeyMeta,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
pub struct GenerateThresholdKey {
    pub re: Re,
    pub meta: ThresholdKeyMeta,
}

impl TryFrom<GenerateKey> for GenerateThresholdKey {
    type Error = GenerateKey;
    fn try_from(req: GenerateKey) -> core::result::Result<GenerateThresholdKey, GenerateKey> {
        match req.meta.threshold {
            Some(threshold) => Ok(GenerateThresholdKey {
                re: req.re,
                meta: ThresholdKeyMeta {
                    name: req.meta.name,
                    algorithm: req.meta.algorithm,
                    threshold,
                    format: req.meta.format,
                }
            }),
            None => Err(req),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
pub struct PrecomputeMeta {
    pub name: String,
    // pub cluster: String,
    pub key: String,
    // default: all cluster nodes
    pub participants: Option<Vec<Participant>>,
}


#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
pub struct GetKey {
    pub re: Re,
    pub name: String,
    pub format: PublicKeyFormat,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
pub struct UnwrapKey {
    pub re: Re,
    pub meta: KeyMeta,
    pub data: WrappedKeyData,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
pub struct ListKeys {
    pub re: Re,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
pub struct ChildMeta {
    pub name: String,
    pub parent: String,
    pub child: u32,
    pub chain_code: Option<[u8; 32]>,
    pub format: PublicKeyFormat,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
pub struct DeriveChildKey {
    pub re: Re,
    pub meta: ChildMeta,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
pub struct Precompute {
    pub re: Re,
    pub meta: PrecomputeMeta,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, Default, schemars::JsonSchema)]
pub struct Sign {
    pub re: Re,
    pub meta: SignatureMeta,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
pub enum Kind {
    GetKey,
    GenerateKey,
    DeriveChildKey,
    GenerateThresholdKey,
    UnwrapKey,
    ListKeys,
    Precompute,
    Sign,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
pub struct WrappedKeyData {
    pub wrapping_key: String,
    pub format: SecretKeyFormat,
    pub wrapped_key: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
pub enum Data {
    Message(Vec<u8>),
    Digest([u8; 32]),
}

impl Default for Data {
    fn default() -> Self { Data::Message(Vec::default()) }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, Default, schemars::JsonSchema)]
pub struct SignatureMeta {
    pub name: String,
    // pub cluster: String,
    pub key: String,
    pub data: Data,
    pub precomputed: Option<String>,
    pub participants: Option<Vec<Participant>>,
    pub format: SignatureFormat,
}

impl Request {
    pub fn kind(&self) -> Kind {
        use Request::*;
        match self {
            GetKey(_) => Kind::GetKey,
            GenerateKey(_) => Kind::GenerateKey,
            // GenerateThresholdKey(_) => Kind::GenerateThresholdKey,
            DeriveChildKey(_) => Kind::DeriveChildKey,
            UnwrapKey(_) => Kind::UnwrapKey,
            ListKeys(_) => Kind::ListKeys,
            Precompute(_) => Kind::Precompute,
            Sign(_) => Kind::Sign,
        }
    }
}

impl Id for Request {
    fn id(&self) -> RequestId {
        use Request::*;
        match self {
            GetKey(r) => r.id(),
            GenerateKey(r) => r.id(),
            // GenerateThresholdKey(r) => r.id(),
            DeriveChildKey(r) => r.id(),
            UnwrapKey(r) => r.id(),
            ListKeys(r) => r.id(),
            Precompute(r) => r.id(),
            Sign(r) => r.id(),
        }
    }
}

impl Short for Request {
    fn short(&self) -> String {
        use Request::*;
        match self {
            GetKey(r) => r.short(),
            GenerateKey(r) => r.short(),
            // GenerateThresholdKey(r) => r.short(),
            DeriveChildKey(r) => r.short(),
            UnwrapKey(r) => r.short(),
            ListKeys(r) => r.short(),
            Precompute(r) => r.short(),
            Sign(r) => r.short(),
        }
    }
}

impl From<GetKey> for Request {
    fn from(request: GetKey) -> Request {
        Request::GetKey(request)
    }
}

impl From<GenerateKey> for Request {
    fn from(request: GenerateKey) -> Request {
        Request::GenerateKey(request)
    }
}

impl From<DeriveChildKey> for Request {
    fn from(request: DeriveChildKey) -> Request {
        Request::DeriveChildKey(request)
    }
}

impl From<ListKeys> for Request {
    fn from(request: ListKeys) -> Request {
        Request::ListKeys(request)
    }
}

impl From<UnwrapKey> for Request {
    fn from(request: UnwrapKey) -> Request {
        Request::UnwrapKey(request)
    }
}

impl From<Precompute> for Request {
    fn from(request: Precompute) -> Request {
        Request::Precompute(request)
    }
}

impl From<Sign> for Request {
    fn from(request: Sign) -> Request {
        Request::Sign(request)
    }
}

impl Id for GetKey { fn id(&self) -> RequestId { self.re.name.clone() } }

impl Short for GetKey {
    fn short(&self) -> String {
        format!("GetKey {} {} ({})", self.name, self.format, self.re.name)
    }
}

impl Id for GenerateKey { fn id(&self) -> RequestId { self.re.name.clone() } }

impl Short for GenerateKey {
    fn short(&self) -> String {
        format!("GenerateKey {} {} {} ({}) {:?}", self.meta.name, self.meta.algorithm, self.meta.format, self.re.name, &self.meta.threshold)
    }
}

impl Id for DeriveChildKey { fn id(&self) -> RequestId { self.re.name.clone() } }

impl Short for DeriveChildKey {
    fn short(&self) -> String {
        format!("DeriveChildKey {} {} {} ({})", self.meta.name, self.meta.child, self.meta.format, self.re.name)
    }
}

impl Id for GenerateThresholdKey { fn id(&self) -> RequestId { self.re.name.clone() } }

impl Short for GenerateThresholdKey {
    fn short(&self) -> String {
        format!("GenerateThresholdKey {} {} ({}/{}) {}",
            self.meta.name, self.meta.algorithm,
            self.meta.threshold.threshold, self.meta.threshold.participants.len(),
            self.meta.format)
    }
}

impl Id for ListKeys { fn id(&self) -> RequestId { self.re.name.clone() } }

impl Short for ListKeys {
    fn short(&self) -> String {
        "ListKeys".to_string()
    }
}

impl Id for UnwrapKey { fn id(&self) -> RequestId { self.re.name.clone() } }

impl Short for UnwrapKey {
    fn short(&self) -> String {
        format!("UnwrapKey {} {} {} from {} {} ({})",
            self.meta.name, self.meta.algorithm, self.meta.format,
            self.data.wrapping_key, self.data.format,
            self.re.name)
    }
}

impl TryFrom<(&[u8], bool)> for Data {
    type Error = Error;
    fn try_from((data, prehashed): (&[u8], bool)) -> Result<Data> {
        Ok(if prehashed {
            Data::Digest(data.try_into()
                .map_err(|_| Error::InvalidDigest(data.len()))?)
        } else {
            Data::Message(data.to_vec())
        })
    }
}

impl Id for Precompute { fn id(&self) -> RequestId { self.re.name.clone() } }

impl Short for Precompute {
    fn short(&self) -> String {
        format!("Precompute {} for {} ({})",
            self.meta.name,
            self.meta.key,
            self.re.name)
    }
}

impl Id for Sign { fn id(&self) -> RequestId { self.re.name.clone() } }

impl Short for Sign {
    fn short(&self) -> String {
        format!("Sign {} {} with {} ({}) {:?}",
            self.meta.name, self.meta.format,
            self.meta.key,
            self.re.name,
            &self.meta.participants)
    }
}

