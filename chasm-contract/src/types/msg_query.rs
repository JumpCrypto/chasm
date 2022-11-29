// use cosmwasm_std::Coin;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
// use crate::types::state::{When, KeyMeta, KeyData, ChildMeta, Re, SignatureMeta};


#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AppQueryMsg {
    // ResolveAddress returns the current address that the name resolves to
    Chasm(Query),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Query {
    Cluster {},
    Key {name: String},
    Keys {},
    PendingGenerateKey {name: String},
    PendingGenerateKeys {},
    PendingSign {name: String},
    PendingSigns {},
    ActiveParticipants {},
}

