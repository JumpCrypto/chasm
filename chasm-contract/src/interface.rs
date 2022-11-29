use std::num::NonZeroU32;

use cosmwasm_std::{
    to_binary, Binary, Deps, DepsMut, Storage, Env, MessageInfo, Response as StdResponse, StdResult,
};

use crate::error::Error;
use crate::{keeper, types::{state::{self, Key}, msg_query::Query}};
use chasm_types::{
    api::{self, request, response, response::Response},
    crypto::{
        SignatureFormat, PublicKeyFormat, Algorithm, Error as ChasmError,
    },
    frost::Error as FrostyError,
};
pub trait ResponseClient {
    fn chasm_generated_key(&self, deps: DepsMut, env: Env, request_name: String, key: &Key);
    fn chasm_signed(&self, deps: DepsMut, env: Env, request_name: String, key: &Key, signature: &Vec<u8>);
}

pub struct  Chasm <T: ResponseClient> {
    client: T,
}

// Update the cluster.  This should only happen on init or migrations.
// Authenticate well before doing this!
pub fn set_cluster(
    storage: &mut dyn Storage,
    cluster: state::Cluster,
) -> StdResult<()> {
    keeper::CLUSTER.save(storage, &cluster)
}

pub fn query(
    deps: Deps,
    _env: Env,
    query: Query,
) -> StdResult<Binary> {
    match query {
        Query::Keys {  } => {
            let all: Vec<(String, state::Key)> = keeper::KEYS
                .range(deps.storage, None, None,cosmwasm_std::Order::Ascending)
                .map(|item| item.unwrap_or(("".into(), Default::default())))
                .collect();
            to_binary(&all)

        }
        Query::Key { name } => {
            let key = keeper::KEYS.load(deps.storage, &name)?;
            to_binary(&key)
        }
        Query::Cluster {  } => {
            let cluster = keeper::CLUSTER.load(deps.storage)?;
            to_binary(&cluster)
        }

        Query::PendingGenerateKeys {  } => {
            let all: Vec<(String, request::GenerateKey)> = keeper::PENDING_KEYS
                .range(deps.storage, None, None,cosmwasm_std::Order::Ascending)
                .map(|item| item.unwrap_or(("".into(), Default::default())))
                .collect();
            to_binary(&all)
        }
        Query::PendingGenerateKey { name } => {
            let key = keeper::PENDING_KEYS.load(deps.storage, &name)?;
            to_binary(&key)
        }
        Query::PendingSigns { } => {
            let all: Vec<(String, request::Sign)> = keeper::PENDING_SIGNS
                .range(deps.storage, None, None,cosmwasm_std::Order::Ascending)
                .map(|item| item.unwrap_or(("".into(), Default::default())))
                .collect();
            to_binary(&all)
        }
        Query::PendingSign { name } => {
            let key = keeper::PENDING_SIGNS.load(deps.storage, &name)?;
            to_binary(&key)
        }
        Query::ActiveParticipants { } => {
            let all: Vec<(String, state::ParticipantHeartbeat)> = keeper::ACTIVE_PARTICIPANTS
                .range(deps.storage, None, None, cosmwasm_std::Order::Ascending)
                .filter(|item| item.is_ok())
                .map(|item| item.unwrap())
                .collect();
            to_binary(&all)
        }
    }
}

pub fn generate_key_request(
    deps: DepsMut,
    env: Env,
    request_name: Option<String>,
    key_name: String,
    algorithm: Algorithm,
    format: PublicKeyFormat,
) -> Result<StdResponse, Error> {
    let cluster = keeper::CLUSTER.load(deps.storage)?;

    let request_name = if let Some(request_name) = request_name {
        request_name
    } else {
        let count = keeper::increment_request_count(deps.storage)?;
        format!("generate-key-{}", count)
    };

    let at = env.block.time.seconds() as i64;

    let re = api::Re {
        name: request_name,
        at: at,
    };

    for participant in &cluster.threshold.participants {
        if !keeper::is_participant_active(deps.storage, *participant) {
            return Err(keeper::not_enough_participants_error(deps.storage))
        }
    }

    let meta = request::KeyMeta {
        name: key_name,
        algorithm: algorithm,
        format: format,
        threshold: Some(cluster.threshold),
    };

    let pending = request::GenerateKey{re, meta};
    if keeper::PENDING_KEYS.has(deps.storage, pending.re.name.as_str()) {
        return Err(Error::AlreadyRequested { re: pending.re });
    }
    if keeper::KEYS.has(deps.storage, pending.meta.name.as_str()) {
        return Err(Error::KeyExists { name: pending.meta.name });
    }

    keeper::PENDING_KEYS.save(deps.storage, pending.re.name.as_str(), &pending)?;

    Ok(StdResponse::default())
}


pub fn sign_request(
    deps: DepsMut,
    env: Env,
    request_name: Option<String>,
    key_name: String,
    message: Vec<u8>,
    format: SignatureFormat,
    // _info: MessageInfo,
    // chasm_req: request::Request,
) -> Result<StdResponse, Error> {
    let cluster = keeper::CLUSTER.load(deps.storage)?;

    let request_name = if let Some(request_name) = request_name {
        request_name
    } else {
        let count = keeper::increment_request_count(deps.storage)?;
        format!("generate-key-{}", count)
    };

    if !keeper::KEYS.has(deps.storage, key_name.as_str()) {
        return Err(Error::KeyNotFound { name: key_name.clone() });
    }

    let at = env.block.time.seconds() as i64;

    let re = api::Re {
        name: request_name,
        at: at,
    };

    let active_participants = keeper::get_active_participants(deps.storage)?;
    if active_participants.len() < cluster.threshold.threshold.get() as usize{
        return Err(keeper::not_enough_participants_error(deps.storage))
    }

    let threshold: u32 = cluster.threshold.threshold.into();
    let mut selected_participants: Vec<NonZeroU32> = Vec::default();
    // select from active participants starting from modulo block height.
    for i in 0 .. threshold {
        selected_participants.push(active_participants[(i as u64 + env.block.height) as usize % active_participants.len()])
    }

    // sanity check we don't select the same participant twice
    assert!(threshold as usize == selected_participants.len());
    for i in 0 .. threshold as usize {
        for j in 0 .. threshold as usize {
            if i != j {
                assert!(selected_participants[i] != selected_participants[j])
            }
        }
    }

    let meta = request::SignatureMeta {
        name: key_name.clone(),
        format: format,
        key: key_name,
        data: request::Data::Message(message),
        participants: Some(selected_participants),
        precomputed: None,
    };

    let pending = request::Sign{re, meta};
    if keeper::PENDING_SIGNS.has(deps.storage, pending.re.name.as_str()) {
        return Err(Error::AlreadyRequested { re: pending.re });
    }

    keeper::PENDING_SIGNS.save(deps.storage, pending.re.name.as_str(), &pending)?;

    Ok(StdResponse::default())
}

impl <T: ResponseClient> Chasm <T>{

    pub fn new(client: T) -> Self {
        Self{client}
    }

    pub fn execute_response(
        &self,
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        response: Response,
    ) -> Result<StdResponse, Error> {
        // check the response is from a valid chasm account
        let cluster = keeper::CLUSTER.load(deps.storage)?;
        let participant = match cluster.get_participant(info.sender.clone()) {
            Some(p) => p,
            None => return Err(Error::Unauthorized {  })
        };
        keeper::mark_active_participant(deps.storage, &env, &participant)?;
        keeper::expire_any_inactive_participants(deps.storage, &env)?;

        match response {
            Response::GenerateKey(res) => {
                self.generated_key(deps, env, res)
            }
            Response::Sign(res) => {
                self.signed(deps, env, res)
            }
            Response::FailedRequest(res) => {
                self.fail(deps, env, res)
            }
            Response::Heartbeat(res) => {
                self.heartbeat(deps, env, info, res)
            }
            _ => {
                Err(Error::Unauthorized {  })
            }
        }
    }

    pub fn generated_key(
        &self,
        deps: DepsMut,
        env: Env,
        response: response::GenerateKey,
    ) -> Result<StdResponse, Error> {
        // TODO verify in cluster that the sender address is the chasm node/participant we expect.

        if let Some(pending) = keeper::PENDING_KEYS.may_load(deps.storage, response.re.name.as_str())? {
            let key = if let Some(key) = keeper::KEYS.may_load(deps.storage, pending.meta.name.as_str())? {
                // This should never happen, but we should "succeed" so we can delete the pending request 
                key
            } else {
                // Create new key
                let key = state::Key {
                    meta: pending.meta,
                    public_key: response.public_key,
                };
                keeper::KEYS.save(deps.storage, key.meta.name.as_str(), &key)?;
                key
            };

            // delete request
            keeper::PENDING_KEYS.remove(deps.storage, response.re.name.as_str());

            // call the client
            self.client.chasm_generated_key(deps, env, response.re.name, &key);

            Ok(
                StdResponse::default()
                    .add_attribute("action", "generated_key")
                    .add_attribute("public_key", base64::encode(&key.public_key))
                    .add_attribute("key_name", &key.meta.name)
            )

        } else {
            Err(Error::RequestNotFound { re: response.re })
        }
    }

    pub fn signed(
        &self,
        deps: DepsMut,
        env: Env,
        response: response::Sign,
    ) -> Result<StdResponse, Error> {
        // TODO verify in cluster that the sender address is the chasm node/participant we expect.

        if let Some(pending) = keeper::PENDING_SIGNS.may_load(deps.storage, response.re.name.as_str())? {

            let key = if let Some(key) = keeper::KEYS.may_load(deps.storage, pending.meta.key.as_str())? {
                key
            } else {
                // we received a signature for a key we don't have record for.
                // We should:
                // 1. Delete the request, as we don't want to be called for this repeatedly.
                // 2. Do not call the client
                // 3. Return success to persist changes
                keeper::PENDING_SIGNS.remove(deps.storage, response.re.name.as_str());
                return Ok(
                    StdResponse::default()
                        .add_attribute("action", "signed")
                        .add_attribute("error", "key not found")
                )
            };
            // verify the signature
            // pending.meta.data
            let verifying_key = chasm_types::crypto::PublicKey::from_raw(key.meta.algorithm, &key.public_key).map_err(|e| Error::InternalCryptoError(e))?;
            let result = match &pending.meta.data {
                request::Data::Digest(digest)=>{
                    verifying_key.verify_digest(digest, &response.signature)
                },
                request::Data::Message(message)=>{
                    verifying_key.verify(message, &response.signature)
                }
            };
            if let Err(err) = result {
                // reject -- let's keep the signing request for now.
                return Err(Error::InternalCryptoError(err))
            } else {
                // signature is valid, we accept.
            }

            // delete request
            keeper::PENDING_SIGNS.remove(deps.storage, response.re.name.as_str());

            // call the client
            self.client.chasm_signed(deps, env, response.re.name, &key, &response.signature);

            Ok(
                StdResponse::default()
                    .add_attribute("action", "signed")
                    .add_attribute("signature", base64::encode(&response.signature))
                    .add_attribute("key_name", &key.meta.name)
                    .add_attribute("name", &pending.meta.name)
            )

        } else {
            Err(Error::RequestNotFound { re: response.re })
        }
    }

    pub fn fail(
        &self,
        deps: DepsMut,
        _env: Env,
        response: response::FailedRequest,
    ) -> Result<StdResponse, Error> {

        println!("FAIL! {:?}", &response);
        match &response.error {
            ChasmError::Frost(FrostyError::InvalidParticipant) => {
                println!("Invalid participant, ignoring");
            },
            _ => {
                println!("err {:?}", response.error);
                println!("dropping request");
                if let Ok(_) = keeper::PENDING_SIGNS.load(deps.storage, response.re.name.as_str()) {
                    keeper::PENDING_SIGNS.remove(deps.storage, response.re.name.as_str())
                }
                if let Ok(_) = keeper::PENDING_KEYS.load(deps.storage, response.re.name.as_str()) {
                    keeper::PENDING_KEYS.remove(deps.storage, response.re.name.as_str())
                }
            }
        }
        Ok(
            StdResponse::default()
                .add_attribute("action", "fail")
                .add_attribute("name", response.re.name.as_str())
                .add_attribute("error", response.error.to_string())
        )
    }

    pub fn heartbeat(
        &self,
        deps: DepsMut,
        _env: Env,
        info: MessageInfo,
        _response: response::Heartbeat,
    ) -> Result<StdResponse, Error> {

        let cluster = keeper::CLUSTER.load(deps.storage)?;
        let participant_id = cluster.get_participant(info.sender).unwrap().participant;

        Ok(
            StdResponse::default()
                .add_attribute("action", "heartbeat")
                .add_attribute("participant", format!("{}", participant_id))
        )
    }

}
