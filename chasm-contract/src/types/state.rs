use std::num::NonZeroU32;

use cosmwasm_std::Addr;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use chasm_types::api::{Re, request::{ChildMeta, KeyMeta, SignatureMeta, ThresholdMeta}};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ParticipantAddress {
    pub participant: NonZeroU32,
    pub address: Addr,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Cluster {
    pub name: String,
    pub threshold: ThresholdMeta,
    pub participant_addresses: Vec<ParticipantAddress>,
}

impl Cluster {
    // check that the participant (id, address) pair is in the genesis
    pub fn is_valid_participant(&self, participant: NonZeroU32, address: Addr) -> bool {
        for paddr in &self.participant_addresses {
            if paddr.participant == participant && address == paddr.address {
                return true
            }
        }
        false
    }
    // check that the participant (id, address) pair is in the genesis
    pub fn get_participant(&self, address: Addr) -> Option<ParticipantAddress> {
        for paddr in &self.participant_addresses {
            if address == paddr.address {
                return Some(paddr.clone())
            }
        }
        None
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema, Default)]
pub struct Key {
    pub meta: KeyMeta,
    #[serde(serialize_with = "chasm_types::base64_serde::serialize", deserialize_with = "chasm_types::base64_serde::deserialize")]
    pub public_key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ParticipantHeartbeat {
    pub participant: ParticipantAddress,
    pub block_height: u64,
}
