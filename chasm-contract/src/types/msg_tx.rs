// use cosmwasm_std::Coin;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use chasm_types::{
    api::response,
    crypto::{Algorithm, PublicKeyFormat, SignatureFormat},
};
use crate::types::state;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    pub cluster: state::Cluster,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    // Externally interact with chasm directly -- never allow in prod
    TestChasm(TestRequest),
    Chasm(response::Response),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TestRequest {
    GenerateKey{
        request_name: Option<String>,
        key_name: String,
        algorithm: Algorithm,
        format: PublicKeyFormat,
    },
    Sign {
        request_name: Option<String>,
        key_name: String,
        message: Vec<u8>,
        format: SignatureFormat,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct MsgMigrate {
    pub comment: String
}