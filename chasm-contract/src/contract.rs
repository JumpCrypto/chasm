// This is how chasm should be used by a client.
use cosmwasm_std::{
    entry_point, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult,
};

use crate::error::Error;
use crate::types::msg_tx::{ExecuteMsg, InstantiateMsg, MsgMigrate, self};
use crate::types::msg_query::{AppQueryMsg};
use crate::types::state::{Key};
use crate::keeper::{TEST_APP_KEYS, TEST_APP_SIGNATURES};

pub struct ChasmClient{}
impl crate::interface::ResponseClient for ChasmClient {
    fn chasm_generated_key(&self, deps: DepsMut, _env: Env, request_name: String, key: &Key) {
        println!("request {} generated key {} with public key {:#02x?}", request_name, key.meta.name.clone(), key.public_key);
        _ = TEST_APP_KEYS.save(deps.storage, key.meta.name.as_str(), &key);
    }

    fn chasm_signed(&self, deps: DepsMut, _env: Env, request_name: String, key: &Key, signature: &Vec<u8>) {
        println!("request {} used {} to produce {:x?} signatures", request_name, key.meta.name.clone(), signature);
        _ = TEST_APP_SIGNATURES.save(deps.storage, request_name.as_str(), signature);
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, StdError> {
    let cluster = msg.cluster;
    crate::interface::set_cluster(deps.storage, cluster)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, Error> {
    let chasm = crate::interface::Chasm::new(ChasmClient{});
    match msg {
        ExecuteMsg::TestChasm ( chasm_request ) => execute_test_chasm(deps, env, info, chasm_request),
        ExecuteMsg::Chasm ( chasm_response ) => chasm.execute_response(deps, env, info, chasm_response),
    }
}


// Testing only
pub fn execute_test_chasm(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    chasm_req: msg_tx::TestRequest,
) -> Result<Response, Error> {

    let mut ret = Response::default();
    match chasm_req {
        msg_tx::TestRequest::GenerateKey { request_name, key_name, algorithm, format } => {
            ret = ret.add_attribute("action", "generate_key")
                    .add_attribute("request", format!("{:?}",request_name))
                    .add_attribute("key_name", key_name.clone())
                    .add_attribute("algorithm", format!("{}",algorithm))
                    .add_attribute("format", format!("{}",format));
            crate::interface::generate_key_request(deps, env, request_name, key_name, algorithm, format)?;
        }
        msg_tx::TestRequest::Sign{ request_name, key_name, message, format } => {
            ret = ret.add_attribute("action", "sign")
                    .add_attribute("request", format!("{:?}",request_name))
                    .add_attribute("key_name", key_name.clone())
                    .add_attribute("format", format!("{}",format));
            crate::interface::sign_request(deps, env, request_name, key_name, message, format)?;
        }
    }

    Ok(ret)
}


#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, env: Env, msg: AppQueryMsg) -> StdResult<Binary> {
    match msg {
        AppQueryMsg::Chasm(query) => crate::interface::query(deps, env, query),
    }
}

#[entry_point]
pub fn migrate(_deps: DepsMut, _env: Env, _msg: MsgMigrate) -> Result<Response, Error> {
    // TODO check contract version is ascending
    Ok(Response::default())
}

