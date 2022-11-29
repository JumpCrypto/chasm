

use std::num::NonZeroU32;
use std::time::Duration;
use cosmwasm_std::testing::{mock_dependencies, mock_env};
use cosmwasm_std::Attribute;
extern crate tracing;

use chasm_types::test_util::TestChasm;
use chasm_types::test_util::TestChasmWithQuerying;

use chasm_types::{
    api::{self, response, response::Response as ChasmResponse},
    cosmos::{HEARTBEAT_BLOCK_PERIOD}, 
    crypto::{
        SignatureFormat, Error as ChasmError,
    },
    frost::Error as FrostyError,
};
use crate::contract;
use crate::error::Error;
use crate::keeper::{self};
use crate::types::{
    msg_tx::{
        ExecuteMsg,
        TestRequest,
    },
};

use crate::test_util::{
    DirectWasmQuerier, ClusterTypeHint,
    gen_rand, generate_taproot_key_request, generate_taproot_sign_request,
    mock_info, mock_env_with, execute_responses, wait_for_heartbeat, send_n_blocks,
    mock_instantiate,
};

#[test_log::test(tokio::test(flavor = "multi_thread"))]
// 1. chasm should query a pending generate key request from the chasm contract
//    and respond correctly
// 2. chasm-contract should delete the request, store the key, and call the test app contract.
async fn chasm_generate_key() {
    let mut deps = mock_dependencies();
    let mut cluster = mock_instantiate(deps.as_mut(),3,4);
    let request_name: String = "r1".into();
    let key_name: String = "r1_generated_key".into();
    wait_for_heartbeat(&mut deps, &mut cluster).await;

    // Send a test request to execise an "API" call to chasm from our test contract.
    let chasm_req = generate_taproot_key_request(&request_name, &key_name);
    contract::execute(deps.as_mut(), mock_env_with(cluster.height()), mock_info(None), chasm_req.clone()).unwrap();

    // Check that 
    // 1. chas has a pending request
    // 2. chasm has no key object
    // 3. the application has no related object.
    assert!(crate::keeper::PENDING_KEYS.has(deps.as_mut().storage, request_name.as_str()));
    assert!(!crate::keeper::KEYS.has(deps.as_mut().storage, key_name.as_str()));
    assert!(!crate::keeper::TEST_APP_KEYS.has(deps.as_mut().storage, key_name.as_str()));

    // Start chasm and execute the pending request(s)
    cluster.start_with_cosmos_dispatch(DirectWasmQuerier::new(&deps.as_ref())).await;
    let _cluster: &mut ClusterTypeHint = &mut cluster;
    let responses = _cluster.process_requests().await;
    cluster.stop().await;

    // Check all responses from each chasm node succeeded
    for res in &responses {
        assert!(matches!(res.response, Ok(ChasmResponse::GenerateKey( _ ))));
    }
    // Pass chasm node responses to the contract and get responses from the contract.
    let results = execute_responses(&mut deps, responses);
    // First response from contract consumes the Pending request and succeeds
    assert!(matches!(&results[0].response, Ok(_)));
    // As the pending request is consumed, subsequent responses fail.
    assert!(matches!(&results[1].response, Err(_)));

    // Check that 
    // 1. the pending request was deleted
    // 2. chasm stored a key object
    // 3. the application stored an object.
    assert!(!crate::keeper::PENDING_KEYS.has(deps.as_mut().storage, request_name.as_str()));
    assert!(crate::keeper::KEYS.has(deps.as_mut().storage, key_name.as_str()));
    assert!(crate::keeper::TEST_APP_KEYS.has(deps.as_mut().storage, key_name.as_str()));
    let key = crate::keeper::KEYS.load(deps.as_mut().storage, key_name.as_str()).unwrap();
    println!("key {:?}", key);
    println!("result {:?}", &results[0]);

    // Check all of the attributes are there
    assert!(results[0].response.as_ref().unwrap().attributes.contains(&Attribute{
        key: "action".into(),
        value: "generated_key".into(),
    }));
    assert!(results[0].response.as_ref().unwrap().attributes.contains(&Attribute{
        key: "public_key".into(),
        value: base64::encode(key.public_key),
    }));
    assert!(results[0].response.as_ref().unwrap().attributes.contains(&Attribute{
        key: "key_name".into(),
        value: key_name.clone(),
    }));
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
// 1. reject if there's an existing request
// 2. reject if there's an existing key with key_name
async fn chasm_generate_key_reject_duplicates() {
    let mut deps = mock_dependencies();
    let mut cluster = mock_instantiate(deps.as_mut(),3,4);
    let request_name: String = "r1".into();
    let key_name: String = "r1_generated_key".into();

    wait_for_heartbeat(&mut deps, &mut cluster).await;
    let chasm_req = generate_taproot_key_request(&request_name, &key_name);
    let res = contract::execute(deps.as_mut(), mock_env(), mock_info(None), chasm_req.clone());
    assert!(matches!(&res, Ok(_)));

    // Duplicate request should return error
    let res = contract::execute(deps.as_mut(), mock_env_with(cluster.height()), mock_info(None), chasm_req.clone());
    assert!(matches!(&res, Err(Error::AlreadyRequested{re:_})));

    // Run the full keygen
    cluster.start_with_cosmos_dispatch(DirectWasmQuerier::new(&deps.as_ref())).await;
    let _cluster: &mut ClusterTypeHint = &mut cluster;
    let responses = _cluster.process_requests().await;
    cluster.stop().await;

    let results = execute_responses(&mut deps, responses);
    assert!(matches!(&results[0].response, Ok(_)));

    // Duplicate request should still return an error.
    let res = contract::execute(deps.as_mut(), mock_env_with(cluster.height()), mock_info(None), chasm_req.clone());
    assert!(res == Err(Error::KeyExists{name: key_name}));
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
// positive test of signing end to end
async fn chasm_sign() {
    let mut deps = mock_dependencies();
    let mut cluster = mock_instantiate(deps.as_mut(),3,4);

    let request_keygen_name: String = "r1-keygen".into();
    let request_sign_name: String = "r1-sign".into();
    let key_name: String = "r1_generated_key".into();
    wait_for_heartbeat(&mut deps, &mut cluster).await;

    // Run the full keygen
    let chasm_req = generate_taproot_key_request(&request_keygen_name, &key_name);
    contract::execute(deps.as_mut(), mock_env_with(cluster.height()), mock_info(None), chasm_req.clone()).unwrap();

    cluster.start_with_cosmos_dispatch(DirectWasmQuerier::new(&deps.as_ref())).await;
    let _cluster: &mut ClusterTypeHint = &mut cluster;
    let responses = _cluster.process_requests().await;
    // cluster.stop().await;

    let results = execute_responses(&mut deps, responses);
    assert!(matches!(&results[0].response, Ok(_)));

    // Issue a signing request
    let chasm_req = ExecuteMsg::TestChasm(TestRequest::Sign {
        request_name:  Some(request_sign_name.clone()), 
        key_name: key_name.clone(),
        message: gen_rand(128), 
        format: SignatureFormat::Raw,
    });
    println!("execute pending sign");
    contract::execute(deps.as_mut(), mock_env_with(cluster.height()), mock_info(None), chasm_req.clone()).unwrap();

    // Peak at the participant assignment our contract used
    let pending_sign = keeper::PENDING_SIGNS.load(deps.as_mut().storage, request_sign_name.as_str()).unwrap();
    let expected_participants = pending_sign.meta.participants.unwrap();

    let _cluster: &mut ClusterTypeHint = &mut cluster;
    let responses = _cluster.process_requests_for(Duration::from_secs(5)).await;
    for i in 0 .. cluster.len() {
        if expected_participants.contains(&responses[i].node.participant) {
            // Expected participants should reply with signature
            assert!(matches!(&responses[i].response, Ok(ChasmResponse::Sign(_))));
        } else {
            // Everyone else should reply fail if they are online
            assert!(matches!(&responses[i].response, Ok(ChasmResponse::FailedRequest(response::FailedRequest{error: ChasmError::Frost(FrostyError::InvalidParticipant), re: _}))));
        }
    }

    let results = execute_responses(&mut deps, responses);
    // Check that 
    // 1. the pending request was deleted
    // 2. test app stored a sign object
    assert!(!crate::keeper::PENDING_SIGNS.has(deps.as_mut().storage, request_sign_name.as_str()));
    assert!(crate::keeper::TEST_APP_SIGNATURES.has(deps.as_mut().storage, request_sign_name.as_str()));
    let signature = crate::keeper::TEST_APP_SIGNATURES.load(deps.as_mut().storage, request_sign_name.as_str()).unwrap();

    let mut sign_count = 0;
    for i in 0 .. cluster.len() {
        // should get a successful response
        println!("contract response to chasm: {:?}", &results[i]);
        if expected_participants.contains(&results[i].node.participant) {
            sign_count = sign_count + 1;
            match sign_count {
                // Only first response will succeed as it deletes the pending request.
                1 => {
                    assert!(matches!(&results[i].response, Ok(_)));
                    // Check all of the attributes are there
                    assert!(results[i].response.as_ref().unwrap().attributes.contains(&Attribute{
                        key: "action".into(),
                        value: "signed".into(),

                    }));
                    assert!(results[i].response.as_ref().unwrap().attributes.contains(&Attribute{
                        key: "signature".into(),
                        value: base64::encode(signature.clone()),
                    }));
                    assert!(results[i].response.as_ref().unwrap().attributes.contains(&Attribute{
                        key: "key_name".into(),
                        value: key_name.clone(),
                    }));
                },
                _ => {
                    assert!(matches!(&results[i].response, Err(Error::RequestNotFound { re:_ })));
                }
            }
        } else {
            // should get successful "failed" responses for invalid participants
            assert!(matches!(&results[i].response, Ok(_)));
            assert!(results[i].response.as_ref().unwrap().attributes.contains(&Attribute{
                key: "action".into(),
                value: "fail".into(),
            }));
            assert!(results[i].response.as_ref().unwrap().attributes.contains(&Attribute{
                key: "name".into(),
                value: request_sign_name.clone(),
            }));
            assert!(results[i].response.as_ref().unwrap().attributes.contains(&Attribute{
                key: "error".into(),
                value: ChasmError::Frost(FrostyError::InvalidParticipant).to_string(),
            }));
        }
    }
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
// Test when a submitted signature is invalid, expect that it gets ignored
async fn chasm_sign_bad_signature() {
    let mut deps = mock_dependencies();
    let mut cluster = mock_instantiate(deps.as_mut(),3,4);
    cluster.start_with_cosmos_dispatch(DirectWasmQuerier::new(&deps.as_ref())).await;
    wait_for_heartbeat(&mut deps, &mut cluster).await;

    let request_keygen_name: String = "r1-gen".into();
    let request_sign_name: String = "r1-sign".into();
    let key_name: String = "r1_generated_key".into();

    // Run the full keygen
    let chasm_req = generate_taproot_key_request(&request_keygen_name, &key_name);
    contract::execute(deps.as_mut(), mock_env_with(cluster.height()), mock_info(None), chasm_req.clone()).unwrap();
    let _cluster: &mut ClusterTypeHint  = &mut cluster;
    let responses = _cluster.process_requests().await;
    execute_responses(&mut deps, responses);

    // Issue a signing request
    let chasm_req = generate_taproot_sign_request(&request_sign_name, &key_name);
    contract::execute(deps.as_mut(), mock_env_with(cluster.height()), mock_info(None), chasm_req.clone()).unwrap();
    let _cluster: &mut ClusterTypeHint  = &mut cluster;
    let mut responses = _cluster.process_requests_for(Duration::from_secs(5)).await;

    // Peak at the participant assignment our contract used
    let pending_sign = keeper::PENDING_SIGNS.load(deps.as_mut().storage, request_sign_name.as_str()).unwrap();
    let expected_participants = pending_sign.meta.participants.unwrap();

    // let's flip a bit in the first signature response
    for i in 0 .. cluster.len() {
        if expected_participants.contains(&responses[i].node.participant) {
            match &mut responses[i].response {
                Ok(ChasmResponse::Sign(response::Sign{re: _, signature})) => {
                    signature[0] = signature[0] ^ 1;
                },
                _ => {
                    panic!("expect successful sign")
                }
            }
            break
        }
    }

    // Now pass chasm responses to the contract
    let results = execute_responses(&mut deps, responses);
    let mut sign_count = 0;
    for i in 0 .. cluster.len() {
        if expected_participants.contains(&results[i].node.participant) {
            sign_count = sign_count + 1;
            match sign_count {
                // First sign we flipped a bit, so it should be rejected
                1 => {
                    assert!(matches!(&results[i].response, Err(Error::InternalCryptoError(ChasmError::InvalidSignature))));
                }
                // Second sign is good, so chasm should accept
                2 => {
                    assert!(matches!(&results[i].response, Ok(_)));
                }
                // Next signs fail as the pending request is consumed
                _ => {
                    assert!(matches!(&results[i].response, Err(Error::RequestNotFound { re:_ })));
                }
            }
        }
    }
    // 3 of 4 nodes
    assert!(sign_count == 3);
}


#[test_log::test(tokio::test(flavor = "multi_thread"))]
// Exercise a failure occuring and deleting a pending request on the contract
async fn chasm_fail_requests() {
    let mut deps = mock_dependencies();
    let mut cluster = mock_instantiate(deps.as_mut(),3,4);
    cluster.start_with_cosmos_dispatch(DirectWasmQuerier::new(&deps.as_ref())).await;
    wait_for_heartbeat(&mut deps, &mut cluster).await;

    let request_name: String = "r1".into();
    let request_name_to_fail: String = "r2_will_fail".into();
    let key_name: String = "r1_generated_key".into();

    // Run a full keygen
    let chasm_req = generate_taproot_key_request(&request_name, &key_name);
    contract::execute(deps.as_mut(), mock_env_with(cluster.height()), mock_info(None), chasm_req.clone()).unwrap();
    let _cluster: &mut ClusterTypeHint = &mut cluster;
    let responses = _cluster.process_requests().await;
    execute_responses(&mut deps, responses);

    // Start a keygen, but we'll fail it.
    let chasm_req = generate_taproot_key_request(&request_name_to_fail, &(key_name.clone().to_owned() + "_2"));
    contract::execute(deps.as_mut(), mock_env_with(cluster.height()), mock_info(None), chasm_req.clone()).unwrap();
    // we should have a pending request
    assert!( keeper::PENDING_KEYS.has(deps.as_mut().storage, request_name_to_fail.as_str()));

    // return failure
    let chasm_failed_res = ExecuteMsg::Chasm(ChasmResponse::FailedRequest(response::FailedRequest{
        re: api::Re {
            name: request_name_to_fail.clone(),
            ..Default::default()
        },
        error: ChasmError::IncompleteRequest,
    }));
    let participant = NonZeroU32::new(1).unwrap();
    let info = mock_info(Some(&cluster.get_node_info_for(participant)));
    contract::execute(deps.as_mut(), mock_env_with(cluster.height()), info.clone(), chasm_failed_res.clone()).unwrap();

    // expect key gen pending is now gone
    assert!( !keeper::PENDING_KEYS.has(deps.as_mut().storage, request_name_to_fail.as_str()));

    // Start a sign, but we'll fail it.
    let chasm_req = generate_taproot_sign_request(&request_name_to_fail, &key_name);
    contract::execute(deps.as_mut(), mock_env_with(cluster.height()), mock_info(None), chasm_req.clone()).unwrap();
    // we should have a pending request
    assert!( keeper::PENDING_SIGNS.has(deps.as_mut().storage, request_name_to_fail.as_str()));
    // now fail the sign request
    contract::execute(deps.as_mut(), mock_env_with(cluster.height()), info.clone(), chasm_failed_res.clone()).unwrap();

    // expect sign pending is now gone
    assert!( !keeper::PENDING_SIGNS.has(deps.as_mut().storage, request_name_to_fail.as_str()));
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
// Test sending a heartbeat and getting a response
async fn chasm_heartbeat() {
    let mut deps = mock_dependencies();
    let mut cluster = mock_instantiate(deps.as_mut(),3,4);

    // we should start out with zero active
    let active = keeper::get_active_participants(&mut deps.storage).unwrap();
    assert!(0 == active.len());

    // after a heatbeart this should change to cluster size
    wait_for_heartbeat(&mut deps, &mut cluster).await;
    let active = keeper::get_active_participants(&mut deps.storage).unwrap();
    assert!(cluster.len() == active.len());

    // 1 of each cluster
    assert!(active.contains(&NonZeroU32::new(1).unwrap()));
    assert!(active.contains(&NonZeroU32::new(2).unwrap()));
    assert!(active.contains(&NonZeroU32::new(3).unwrap()));
    assert!(active.contains(&NonZeroU32::new(4).unwrap()));

    // after waiting for a 2x heartbeat period, contract should timeout active participants.
    _ = send_n_blocks(&mut deps, &mut cluster, 3 * HEARTBEAT_BLOCK_PERIOD).await;

    // send a chasm response just to "crank" the contract
    println!("sending crank");
    let info = mock_info(Some(&cluster.get_node_info_for(NonZeroU32::new(1).unwrap())));
    _ = contract::execute(deps.as_mut(), mock_env_with(cluster.height()), info, ExecuteMsg::Chasm(response::Response::FailedRequest(response::FailedRequest{
        error: ChasmError::Malfeasance,
        re: Default::default(),
    })));

    // now only one active, the crank-turner
    let active = keeper::get_active_participants(&mut deps.storage).unwrap();
    assert!(1 == active.len());
    assert!(active.contains(&NonZeroU32::new(1).unwrap()));

    // send a heartbeat by another node
    let info = mock_info(Some(&cluster.get_node_info_for(NonZeroU32::new(2).unwrap())));
    _ = contract::execute(deps.as_mut(), mock_env_with(cluster.height()), info, ExecuteMsg::Chasm(response::Response::Heartbeat(response::Heartbeat{
        re: Default::default(),
    })));
    let active = keeper::get_active_participants(&mut deps.storage).unwrap();
    assert!(2 == active.len());
    assert!(active.contains(&NonZeroU32::new(2).unwrap()));

}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
// Here we will purposely timeout a node before generating a key.
// then when we attempt to generate a key, we will get an error about
// not enough active node.
async fn chasm_cannot_keygen_with_inactive_nodes() {
    let mut deps = mock_dependencies();
    let mut cluster = mock_instantiate(deps.as_mut(),3,4);
    cluster.start_with_cosmos_dispatch(DirectWasmQuerier::new(&deps.as_ref())).await;
    let request_name: String = "r1".into();
    let key_name: String = "r1_generated_key".into();
    wait_for_heartbeat(&mut deps, &mut cluster).await;

    // let's wait enough time for there to be a timeout, 3 periods
    let responses = send_n_blocks(&mut deps, &mut cluster, HEARTBEAT_BLOCK_PERIOD * 3).await;

    // there should be three heartbeats sent in this time (12 total = 4 node * 3 beats)
    assert!(12 == responses.len());

    // now let's send the last heartbeat for all but 1 node.
    let responses = Vec::from(&responses[9..]);
    let results = execute_responses(&mut deps, responses);
    for res in &results {
        assert!(matches!(res.response, Ok(_)));
    }

    // generating keygen should cause error
    let chasm_req = generate_taproot_key_request(&request_name, &key_name);
    let res = contract::execute(deps.as_mut(), mock_env_with(cluster.height()), mock_info(None), chasm_req.clone());

    let expected_active = vec![NonZeroU32::new(2).unwrap(),NonZeroU32::new(3).unwrap(),NonZeroU32::new(4).unwrap()];
    let expected_inactive = vec![NonZeroU32::new(1).unwrap()];

    match res {
        Err(Error::NotEnoughActiveParticipants { active, inactive }) => {
            assert!(active == expected_active);
            assert!(inactive == expected_inactive);
        },
        _ => {
            panic!("did not return expected error")
        }
    }
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
// Here we will purposely timeout a node before generating a key.
// then when we attempt to generate a key, we will get an error about
// not enough active node.
async fn chasm_cannot_sign_with_inactive_nodes() {
    let mut deps = mock_dependencies();
    let mut cluster = mock_instantiate(deps.as_mut(),3,4);
    cluster.start_with_cosmos_dispatch(DirectWasmQuerier::new(&deps.as_ref())).await;
    let request_name: String = "r1".into();
    let key_name: String = "r1_generated_key".into();
    wait_for_heartbeat(&mut deps, &mut cluster).await;

    // Run a full keygen
    let chasm_req = generate_taproot_key_request(&request_name, &key_name);
    contract::execute(deps.as_mut(), mock_env_with(cluster.height()), mock_info(None), chasm_req.clone()).unwrap();
    // rust breaks without this "type hint"
    let _cluster: &mut ClusterTypeHint = &mut cluster;
    let responses = _cluster.process_requests().await;
    execute_responses(&mut deps, responses);

    // let's wait enough time for there to be a timeout, 3 periods
    let responses = send_n_blocks(&mut deps, &mut cluster, HEARTBEAT_BLOCK_PERIOD * 3).await;

    assert!(12 == responses.len());

    // now let's send a heartbeat for all but 1 node.
    let responses = Vec::from(&responses[9..]);
    let results = execute_responses(&mut deps, responses);
    for res in &results {
        assert!(matches!(res.response, Ok(_)));
    }

    // we expect the active set to have 1 missing node.
    let active = keeper::get_active_participants(&mut deps.storage).unwrap();
    for p in active {
        assert!(p.get() != 1);
    }

    // signing should still work as it's a 3-of-4 threshold
    let chasm_req = generate_taproot_sign_request(&request_name, &key_name);
    contract::execute(deps.as_mut(), mock_env_with(cluster.height()), mock_info(None), chasm_req.clone()).unwrap();
    // let's peak at the pending sign and assert that node 0 was not selected.
    let pending_sign = crate::keeper::PENDING_SIGNS.load(deps.as_mut().storage, request_name.as_str()).unwrap();
    let expected_active = vec![NonZeroU32::new(2).unwrap(),NonZeroU32::new(3).unwrap(),NonZeroU32::new(4).unwrap()];
    let mut participants = pending_sign.meta.participants.unwrap();
    participants.sort();
    assert!(participants == expected_active);

    // follow through with the rest of the sign
    let _cluster: &mut ClusterTypeHint = &mut cluster;
    let responses = _cluster.process_requests().await;
    let results = execute_responses(&mut deps, responses);
    for i in 0 .. results.len() {
        if expected_active.contains(&results[i].node.participant) {
            // only need to check first success
            assert!(matches!(&results[i].response, Ok(_)));
            break;
        }
    }

    // now let's timeout two nodes and expect signing to fail.
    let responses = send_n_blocks(&mut deps, &mut cluster, HEARTBEAT_BLOCK_PERIOD * 3).await;
    assert!(12 == responses.len());
    // send beats for last two
    let responses = Vec::from(&responses[10..]);
    let results = execute_responses(&mut deps, responses);
    for res in &results {
        assert!(matches!(res.response, Ok(_)));
    }
    // two missing nodes
    let active = keeper::get_active_participants(&mut deps.storage).unwrap();
    for p in active {
        assert!(p.get() != 1 && p.get() != 2);
    }

    // expect failure
    let chasm_req = generate_taproot_sign_request(&request_name, &key_name);
    let res = contract::execute(deps.as_mut(), mock_env_with(cluster.height()), mock_info(None), chasm_req.clone());

    match res {
        Err(Error::NotEnoughActiveParticipants { active, inactive }) => {
            assert!(active == vec![NonZeroU32::new(3).unwrap(),NonZeroU32::new(4).unwrap()]);
            assert!(inactive == vec![NonZeroU32::new(1).unwrap(),NonZeroU32::new(2).unwrap()]);
        },
        _ => {
            panic!("did not return expected error")
        }
    }
}