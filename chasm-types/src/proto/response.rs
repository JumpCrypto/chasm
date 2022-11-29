//! Integration of Trussed response types with protobuf messages.
//! 
//! One challenge is the inclusion of the account string / address
//! into the cosmos proto "tx" message, which does not make sense to include
//! in native cosmos types.
//! The solution is to define wrapper types here for each Trussed response
//! that each contains the "native" response, and additional info needed for cosmos,
//! which just seems to be the account/address string.
//! 
//! This `Cosmos<ResponseName>` type is used to define From traits for into protobuf messages.

use std::str::FromStr;
use cosmrs::{
    ErrorReport,
    tx::{Msg, MsgProto},
};

use super::chasm as proto;

pub use crate::api::{Id, Short, response::{
    self,
    // Data,
    DeriveChildKey,
    GenerateKey,
    // KeyMeta,
    Response,
    Sign,
    // SignatureMeta,
    UnwrapKey,
    // WrappedKeyData,
    FailedRequest,
    Heartbeat,
}};

// For wasm ExecuteMsg dispatch
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    Chasm(Response),
}

impl MsgProto for super::cosmwasm::wasm::v1::MsgExecuteContract {
    const TYPE_URL: &'static str = "/cosmwasm.wasm.v1.MsgExecuteContract";
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize)]
pub struct CosmosDeriveChildKey{
    account_id: cosmrs::AccountId,
    derive_key: DeriveChildKey,
}

impl CosmosDeriveChildKey {
    pub fn new(derive_key: DeriveChildKey, account_id: &cosmrs::AccountId) -> Self {
        Self{derive_key, account_id: account_id.clone()}
    }
}

impl MsgProto for proto::MsgDerivedChildKey {
    const TYPE_URL: &'static str = "/chasm.MsgDerivedChildKey";
}

impl Msg for CosmosDeriveChildKey {
    type Proto = proto::MsgDerivedChildKey;
}

impl From<CosmosDeriveChildKey> for proto::MsgDerivedChildKey {
    fn from(response: CosmosDeriveChildKey) -> proto::MsgDerivedChildKey {
        (&response).into()
    }
}

impl From<&CosmosDeriveChildKey> for proto::MsgDerivedChildKey {
    fn from(response: &CosmosDeriveChildKey) -> proto::MsgDerivedChildKey {
        proto::MsgDerivedChildKey {
            responder: response.account_id.to_string(),
            re: Some((&response.derive_key.re).into()),
            data: Some(proto::KeyData {
                public_key: response.derive_key.public_key.clone(),
            }),
        }
    }
}

impl TryFrom<proto::MsgDerivedChildKey> for CosmosDeriveChildKey {
    type Error = ErrorReport;
    fn try_from(_: proto::MsgDerivedChildKey) -> Result<Self, Self::Error> {
        todo!();
    }
}

impl From<CosmosDeriveChildKey> for DeriveChildKey {
    fn from(response: CosmosDeriveChildKey) -> DeriveChildKey {
        response.derive_key
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize)]
pub struct CosmosGenerateKey {
    account_id: cosmrs::AccountId,
    generate_key: GenerateKey,
}

impl CosmosGenerateKey {
    pub fn new(generate_key: GenerateKey, account_id: &cosmrs::AccountId) -> Self {
        Self{generate_key, account_id: account_id.clone()}
    }
}

impl MsgProto for proto::MsgGeneratedKey {
    const TYPE_URL: &'static str = "/chasm.MsgGeneratedKey";
}

impl Msg for CosmosGenerateKey {
    type Proto = proto::MsgGeneratedKey;
}

impl From<CosmosGenerateKey> for proto::MsgGeneratedKey {
    fn from(response: CosmosGenerateKey) -> proto::MsgGeneratedKey {
        (&response).into()
    }
}

impl From<&CosmosGenerateKey> for proto::MsgGeneratedKey {
    fn from(response: &CosmosGenerateKey) -> proto::MsgGeneratedKey {
        proto::MsgGeneratedKey {
            responder: response.account_id.to_string(),
            re: Some((&response.generate_key.re).into()),
            data: Some(proto::KeyData {
                public_key: response.generate_key.public_key.clone(),
            }),
        }
    }
}

impl TryFrom<proto::MsgGeneratedKey> for CosmosGenerateKey {
    type Error = ErrorReport;
    fn try_from(msg: proto::MsgGeneratedKey) -> Result<Self, Self::Error> {
        Ok(CosmosGenerateKey {
            account_id: cosmrs::AccountId::from_str(msg.responder.as_str())?,
            generate_key: GenerateKey { 
                public_key: msg.data.unwrap().public_key,
                re: (&msg.re.unwrap()).try_into().unwrap(),
            }
        })
    }
}

impl From<CosmosGenerateKey> for GenerateKey {
    fn from(response: CosmosGenerateKey) -> GenerateKey {
        response.generate_key
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize)]
pub struct CosmosUnwrapKey {
    account_id: cosmrs::AccountId,
    unwrap_key: UnwrapKey,
}

impl CosmosUnwrapKey {
    pub fn new(unwrap_key: UnwrapKey, account_id: &cosmrs::AccountId) -> Self {
        Self{unwrap_key, account_id: account_id.clone()}
    }
}

impl MsgProto for proto::MsgUnwrappedKey {
    const TYPE_URL: &'static str = "/chasm.MsgUnwrappedKey";
}

impl Msg for CosmosUnwrapKey {
    type Proto = proto::MsgUnwrappedKey;
}

impl From<CosmosUnwrapKey> for proto::MsgUnwrappedKey {
    fn from(response: CosmosUnwrapKey) -> proto::MsgUnwrappedKey {
        (&response).into()
    }
}

impl From<&CosmosUnwrapKey> for proto::MsgUnwrappedKey {
    fn from(response: &CosmosUnwrapKey) -> proto::MsgUnwrappedKey {
        proto::MsgUnwrappedKey {
            responder: response.account_id.to_string(),
            re: Some((&response.unwrap_key.re).into()),
            data: Some(proto::KeyData {
                public_key: response.unwrap_key.public_key.clone(),
            }),
        }
    }
}

impl TryFrom<proto::MsgUnwrappedKey> for CosmosUnwrapKey {
    type Error = ErrorReport;
    fn try_from(msg: proto::MsgUnwrappedKey) -> Result<Self, Self::Error> {
        Ok(CosmosUnwrapKey {
            account_id: cosmrs::AccountId::from_str(msg.responder.as_str())?,
            unwrap_key: UnwrapKey {
                re: (&msg.re.unwrap()).try_into().unwrap(),
                public_key: msg.data.unwrap().public_key,
            },
        })
    }
}

impl From<CosmosUnwrapKey> for UnwrapKey {
    fn from(response: CosmosUnwrapKey) -> UnwrapKey {
        response.unwrap_key
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize)]
pub struct CosmosSign {
    account_id: cosmrs::AccountId,
    sign: Sign,
}

impl CosmosSign {
    pub fn new(sign: Sign, account_id: &cosmrs::AccountId) -> Self {
        Self{sign, account_id: account_id.clone()}
    }
}

impl MsgProto for proto::MsgSigned {
    const TYPE_URL: &'static str = "/chasm.MsgSigned";
}

impl Msg for CosmosSign {
    type Proto = proto::MsgSigned;
}

impl From<CosmosSign> for proto::MsgSigned {
    fn from(response: CosmosSign) -> proto::MsgSigned {
        (&response).into()
    }
}

impl From<&CosmosSign> for proto::MsgSigned {
    fn from(response: &CosmosSign) -> proto::MsgSigned {
        proto::MsgSigned {
            responder: response.account_id.to_string(),
            re: Some((&response.sign.re).into()),
            data: Some(proto::SignatureData {
                signature: response.sign.signature.clone(),
            }),
        }
    }
}

impl TryFrom<proto::MsgSigned> for CosmosSign {
    type Error = ErrorReport;
    fn try_from(msg: proto::MsgSigned) -> Result<Self, Self::Error> {
        Ok(CosmosSign{
            account_id: cosmrs::AccountId::from_str(msg.responder.as_str())?,
            sign: Sign {
                re: (&msg.re.unwrap()).try_into().unwrap(),
                signature: msg.data.unwrap().signature,
            },
        })
    }
}

impl From<CosmosSign> for Sign {
    fn from(response: CosmosSign) -> Sign{
        response.sign
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize)]
pub struct CosmosFailedRequest {
    account_id: cosmrs::AccountId,
    fail: FailedRequest,
}

impl CosmosFailedRequest {
    pub fn new(fail: FailedRequest, account_id: &cosmrs::AccountId) -> Self {
        Self{fail, account_id: account_id.clone()}
    }
}


impl MsgProto for proto::MsgFailedRequest {
    const TYPE_URL: &'static str = "/chasm.MsgFailedRequest";
}

impl Msg for CosmosFailedRequest {
    type Proto = proto::MsgFailedRequest;
}

impl From<CosmosFailedRequest> for proto::MsgFailedRequest {
    fn from(response: CosmosFailedRequest) -> proto::MsgFailedRequest {
        // WTF ?!?!?!?!?!
        // Without an explicit conversion to reference,
        // this method calls itself recursively
        // (leading to a stack overflow)
        //
        // Why does this happen for FailedRequest, but not GenerateKey + friends ?!
        (&response).into()
    }
}

impl From<&CosmosFailedRequest> for proto::MsgFailedRequest {
    fn from(response: &CosmosFailedRequest) -> Self {
        let rep = Self {
            responder: response.account_id.to_string(),
            re: Some((&response.fail.re).into()),
            data: Some(proto::FailedRequestData {
                error: format!("{:?}", response.fail.error),
            }),
        };
        rep
    }
}

impl TryFrom<proto::MsgFailedRequest> for CosmosFailedRequest {
    type Error = ErrorReport;
    fn try_from(msg: proto::MsgFailedRequest) -> Result<Self, Self::Error> {
        Ok(CosmosFailedRequest {
            account_id: cosmrs::AccountId::from_str(msg.responder.as_str())?,
            fail: FailedRequest{
                re: (&msg.re.unwrap()).try_into().unwrap(),
                error: crate::crypto::Error::FailedRequest(msg.data.unwrap().error),
            }
        })
    }
}

impl From<CosmosFailedRequest> for FailedRequest {
    fn from(response: CosmosFailedRequest) -> FailedRequest {
        response.fail
    }
}


#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize)]
pub struct CosmosHeartbeat {
    account_id: cosmrs::AccountId,
    heartbeat: Heartbeat,
}

impl CosmosHeartbeat {
    pub fn new(heartbeat: Heartbeat, account_id: &cosmrs::AccountId) -> Self {
        Self{heartbeat, account_id: account_id.clone()}
    }
}


impl MsgProto for proto::MsgHeartbeat {
    const TYPE_URL: &'static str = "/chasm.MsgHeartbeat";
}

impl Msg for CosmosHeartbeat {
    type Proto = proto::MsgHeartbeat;
}

impl From<CosmosHeartbeat> for proto::MsgHeartbeat {
    fn from(response: CosmosHeartbeat) -> proto::MsgHeartbeat {
        // WTF ?!?!?!?!?!
        // Without an explicit conversion to reference,
        // this method calls itself recursively
        // (leading to a stack overflow)
        //
        // Why does this happen for FailedRequest, but not GenerateKey + friends ?!
        (&response).into()
    }
}

impl From<&CosmosHeartbeat> for proto::MsgHeartbeat {
    fn from(response: &CosmosHeartbeat) -> Self {
        let rep = Self {
            responder: response.account_id.to_string(),
            re: Some((&response.heartbeat.re).into()),
        };
        rep
    }
}

impl TryFrom<proto::MsgHeartbeat> for CosmosHeartbeat {
    type Error = ErrorReport;
    fn try_from(msg: proto::MsgHeartbeat) -> Result<Self, Self::Error> {
        Ok(CosmosHeartbeat {
            account_id: cosmrs::AccountId::from_str(msg.responder.as_str())?,
            heartbeat: Heartbeat{
                re: (&msg.re.unwrap()).try_into().unwrap(),
            }
        })
    }
}

impl From<CosmosHeartbeat> for Heartbeat {
    fn from(response: CosmosHeartbeat) -> Heartbeat {
        response.heartbeat
    }
}
