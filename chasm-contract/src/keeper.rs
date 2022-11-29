use std::num::NonZeroU32;
use cosmwasm_std::{StdResult, Storage, Env};
use cw_storage_plus::{Item, Map};

use chasm_types::{
    api::request, cosmos::HEARTBEAT_BLOCK_PERIOD,
};
use crate::types::state;
use crate::error::Error;

pub const CLUSTER: Item<state::Cluster> = Item::new("cluster");

pub const REQUEST_COUNT: Item<u64> = Item::new("request-count");

pub const PENDING_KEYS: Map<&str, request::GenerateKey> = Map::new("pending-key");
pub const PENDING_SIGNS: Map<&str, request::Sign> = Map::new("pending-key");

pub const ACTIVE_PARTICIPANTS: Map<&str, state::ParticipantHeartbeat> = Map::new("active-participants");

pub const KEYS: Map<&str, state::Key> = Map::new("key");
pub const TEST_APP_KEYS: Map<&str, state::Key> = Map::new("key");
pub const TEST_APP_SIGNATURES: Map<&str, Vec<u8>> = Map::new("key");

pub fn increment_request_count(storage: &mut dyn Storage) -> StdResult<u64> {
    let count = 
    if let Ok(count) = REQUEST_COUNT.may_load(storage) {
        if let Some(count) = count {
            count
        } else {
            0
        }
    } else {
        0
    };
    REQUEST_COUNT.save(storage, &(count+1))?;
    Ok(count)
}

// remove chasm nodes that haven't been sending any liveness indication for some period
pub fn get_active_participants(storage: &mut dyn Storage) -> Result<Vec<NonZeroU32>, Error> {
    let cluster = CLUSTER.load(storage)?;
    let mut active: Vec<NonZeroU32> = Default::default();
    for participant in &cluster.threshold.participants {
        if is_participant_active(storage, *participant) {
            active.push(*participant)
        }
    }
    Ok(active)
}

pub fn expire_any_inactive_participants(storage: &mut dyn Storage, env: &Env) -> Result<(), Error> {
    let query: StdResult<Vec<_>> = ACTIVE_PARTICIPANTS.range(storage, None, None, cosmwasm_std::Order::Ascending).collect();
    let participants = query?;
    if env.block.height > 2 * HEARTBEAT_BLOCK_PERIOD {
        let cutoff = env.block.height - 2 * HEARTBEAT_BLOCK_PERIOD;
        for (key, participant) in participants {
            if env.block.height < 2 * HEARTBEAT_BLOCK_PERIOD {
                continue
            }
            if participant.block_height <= cutoff {
                // expired
                ACTIVE_PARTICIPANTS.remove(storage, &key)
            }
        }
    }
    Ok(())
}

// update a node as active
pub fn mark_active_participant(storage: &mut dyn Storage, env: &Env, participant: &state::ParticipantAddress) -> Result<(), Error> {
    let k = format!("p{}", participant.participant);
    ACTIVE_PARTICIPANTS.save(storage, &k, &state::ParticipantHeartbeat { 
        participant: participant.clone(),
        block_height: env.block.height, 
    })?;
    Ok(())
}

pub fn is_participant_active(storage: &mut dyn Storage, participant: NonZeroU32) -> bool {
    let k = format!("p{}", participant);
    ACTIVE_PARTICIPANTS.has(storage, &k)
}

pub fn not_enough_participants_error(storage: &mut dyn Storage) -> Error {
    let cluster = CLUSTER.load(storage).unwrap();
    let mut active: Vec<NonZeroU32> = Default::default();
    let mut inactive: Vec<NonZeroU32> = Default::default();
    for participant in &cluster.threshold.participants {
        if !is_participant_active(storage, *participant) {
            inactive.push(*participant)
        } else {
            active.push(*participant)
        }
    }
    Error::NotEnoughActiveParticipants { active, inactive }
}