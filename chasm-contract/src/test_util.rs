use std::sync::{Arc, Mutex};
use std::num::NonZeroU32;
use std::time::Duration;

use cosmwasm_std::testing::{mock_env, mock_info as mock_std_info, MockStorage, MockApi, MockQuerier};
use cosmwasm_std::{Deps, OwnedDeps, DepsMut, Response as StdResponse, Empty, Addr, from_binary};

use chasm_types::test_util::TestChasm;
use chasm_types::test_util::TestChasmWithQuerying;

extern crate tracing;

use chasm_types::{
    api::{request, response,},
    cosmos::{QueryClient, HEARTBEAT_BLOCK_PERIOD}, error::Error as RpcError,
    crypto::{
        SignatureFormat, PublicKeyFormat, Algorithm, Error as ChasmError,
    },
    test_util::{
        NodeResponse,
        NodeInfo,
    },
};

use crate::types::{
    state,
    msg_tx::{
        InstantiateMsg,
        ExecuteMsg,
        TestRequest,
    },
};

use crate::contract;
use crate::types::{
    msg_query::{
        AppQueryMsg,
        Query,
    },
};

// TODO use "real" chasm implementation when it's published.
pub type ClusterTypeHint = dyn chasm_types::test_util::TestChasmWithQuerying<DirectWasmQuerier> + Send + Sync;
// use chasm::test_util::ChasmCluster;
// Dumb chasm implementation
pub type ChasmCluster = chasm_types::test_util::ChasmClusterWithQuerying<DirectWasmQuerier>;

pub fn generate_taproot_key_request(request_name: &String, key_name: &String) -> ExecuteMsg {
    ExecuteMsg::TestChasm(TestRequest::GenerateKey{
        request_name:  Some(request_name.clone()), 
        key_name: key_name.clone(),
        algorithm: Algorithm::K256Taproot,
        format: PublicKeyFormat::Raw,
    })
}

pub fn generate_taproot_sign_request(request_name: &String, key_name: &String) -> ExecuteMsg {
    ExecuteMsg::TestChasm(TestRequest::Sign {
        request_name:  Some(request_name.clone()), 
        key_name: key_name.clone(),
        message: gen_rand(128), 
        format: SignatureFormat::Raw,
    })
}

pub fn mock_env_with(height: u64) -> cosmwasm_std::Env {
    let mut env = mock_env();
    env.block.height = height;
    return env
}

pub fn mock_instantiate(deps: DepsMut, k_threshold: u32, n_num_participants: u32) -> ChasmCluster {
    let env = mock_env();
    let info = mock_info(None);
    assert!(k_threshold <= n_num_participants);

    let cluster = ChasmCluster::new(4, Duration::from_millis(1000));
    let mut participants: Vec<NonZeroU32> = Default::default();
    let mut participant_addresses: Vec<state::ParticipantAddress> = Default::default();
    for i in 1 .. n_num_participants + 1 {
        let node  = cluster.get_node_info_for(NonZeroU32::new(i).unwrap());
        participants.push(node.participant);
        let address: &str = node.account_id.as_ref();
        participant_addresses.push(state::ParticipantAddress{
            participant: node.participant,
            address: Addr::unchecked(address),
        });
    }

    let msg = InstantiateMsg{
        cluster: state::Cluster{
            name: "mycluster".into(),
            threshold: request::ThresholdMeta {
                threshold: NonZeroU32::new(k_threshold).unwrap(),
                participants,
            },
            participant_addresses,
        },
    };
    contract::instantiate(deps, env, info, msg).unwrap();

    cluster
}

pub async fn send_n_blocks(deps:  &mut OwnedDeps<MockStorage, MockApi, MockQuerier, Empty>, cluster: &mut ChasmCluster, n: u64) -> Vec<NodeResponse> {
    let mut do_stop = false;
    if !cluster.has_started() {
        cluster.start_with_cosmos_dispatch(DirectWasmQuerier::new(&deps.as_ref())).await;
        do_stop = true;
    }
    let mut all_responses: Vec<NodeResponse> = Default::default();

    for _ in 0 .. (n + 1) {
        // give time for chasm dispatch thread to process the block and _maybe_ reply.
        // warning: this might cause flaky tests in some environments if this delay isn't sufficient
        let _cluster: &mut ClusterTypeHint = cluster;
        let mut responses = _cluster.process_requests_for(Duration::from_micros(1200)).await;
        responses = responses.into_iter().filter(|r| {
            match r.response {
                Err(ChasmError::TimedOut(_)) => false,
                _ => true
            }
        }).collect();
        all_responses.extend(responses);
    }

    if do_stop {
        cluster.stop().await;
    }
    return all_responses;
}

pub async fn wait_for_heartbeat(deps:  &mut OwnedDeps<MockStorage, MockApi, MockQuerier, Empty>, cluster: &mut ChasmCluster) {

    let responses = send_n_blocks(deps, cluster, HEARTBEAT_BLOCK_PERIOD).await;

    assert!(responses.len() == cluster.len());
    for res in &responses {
        assert!(matches!(res.response, Ok(response::Response::Heartbeat(_))));
    }
    println!("passing in the heatbearts");
    // pass in the heartbeats
    let results = execute_responses(deps, responses);
    for res in results {
        assert!(matches!(res.response, Ok(_)));
    }
    println!("done");
}

#[derive(Debug)]
pub struct ContractResponse {
    pub response: Result<StdResponse, crate::error::Error>,
    pub node: NodeInfo,
}

pub fn execute_responses(deps: &mut OwnedDeps<MockStorage, MockApi, MockQuerier, Empty>, chasm_responses: Vec<NodeResponse>) -> Vec<ContractResponse> {
    let mut results = Vec::default();
    for res in chasm_responses {
        let result = contract::execute(deps.as_mut(), mock_env_with(res.height), mock_info(Some(&res.node)), ExecuteMsg::Chasm(res.response.unwrap()));
        results.push(ContractResponse{
            response: result,
            node: res.node,
        });
    }
    results
}

pub fn mock_info(addr_maybe: Option<&NodeInfo>) -> cosmwasm_std::MessageInfo {
    if let Some(addr) =addr_maybe {
        mock_std_info(addr.account_id.as_ref(), &[])
    } else {
        const SENDER_ADDRESS: &str= "wasm1qq-external_account";
        mock_std_info(SENDER_ADDRESS, &[])
    }
}



#[derive(Clone)]
pub struct DirectWasmQuerier{
    // deps_ptr: usize,
    locked_ptr: Arc<Mutex<usize>>
}

impl DirectWasmQuerier {
    pub fn new(deps: &Deps) -> Self{
        // 1/2 bypass Send restriction
        let deps = Box::new(*deps);
        let deps = Box::leak(deps);
        Self{ 
            locked_ptr: Arc::new(Mutex::new((deps as *const Deps) as usize))
            // deps_ptr: 
        }
    }
}

#[async_trait::async_trait]
impl QueryClient for DirectWasmQuerier {
    async fn connect(&mut self, _grpc_endpoint: &str) -> Result<(), RpcError> {
        Ok(())
    }
    async fn pending_generate_keys(&mut self) -> Result<(Vec<request::GenerateKey>, Vec<response::FailedRequest>), tonic::Status> {
        // 2/2 bypass Send restriction
        let deps_ptr = *self.locked_ptr.lock().unwrap();

        let deps = unsafe{*(deps_ptr as *const Deps)};
        let query = AppQueryMsg::Chasm(Query::PendingGenerateKeys {  });
        let q_bz = contract::query(deps, mock_env(), query).unwrap();
        let pending_requests: Vec<(String, request::GenerateKey)> = from_binary(&q_bz).unwrap();
        let pending_requests: Vec<(String, request::GenerateKey)> = pending_requests.into_iter().filter(|p| p.0.len() > 0).collect();
        let pending_requests = pending_requests.into_iter().map(|p| p.1).collect();
        Ok((pending_requests, Vec::default()))
    }
    async fn pending_derive_child_keys(&mut self) -> Result<(Vec<request::DeriveChildKey>, Vec<response::FailedRequest>), tonic::Status> {
        Ok((Vec::default(), Vec::default()))
    }
    async fn pending_unwrap_keys(&mut self) -> Result<(Vec<request::UnwrapKey>, Vec<response::FailedRequest>), tonic::Status> {
        Ok((Vec::default(), Vec::default()))
    }
    async fn pending_signs(&mut self) -> Result<(Vec<request::Sign>, Vec<response::FailedRequest>), tonic::Status> {
        // println!("calling pending signs");
        let deps_ptr = *self.locked_ptr.lock().unwrap();
        let deps = unsafe{*(deps_ptr as *const Deps)};
        let query = AppQueryMsg::Chasm(Query::PendingSigns {  });
        let q_bz = contract::query(deps, mock_env(), query).unwrap();
        let pending_requests: Vec<(String, request::Sign)> = from_binary(&q_bz).unwrap();
        let pending_requests: Vec<(String, request::Sign)> = pending_requests.into_iter().filter(|p| p.0.len() > 0).collect();
        let pending_requests = pending_requests.into_iter().map(|p| p.1).collect();
        // println!("pending signs: {:?}", pending_requests);
        Ok((pending_requests, Vec::default()))
    }
}

pub fn gen_rand(length: usize) -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let vals: Vec<u8> = (0..length).map(|_| rng.gen_range(0 .. 256) as u8).collect();
    vals
}

