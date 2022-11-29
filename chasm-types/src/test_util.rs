
use std::num::NonZeroU32;
use std::time::Duration;
pub use std::collections::{BTreeSet as Set};
use crate::api::{request, response, self};
use crate::cosmos::{QueryClient, HEARTBEAT_BLOCK_PERIOD};
use crate::crypto::{self};
use crate::frost::{self};
use async_trait::async_trait;

#[derive(Clone, Debug)]
pub struct NodeInfo {
    pub participant: crate::Participant,
    pub account_id: cosmrs::AccountId,
}

#[derive(Clone, Debug)]
pub struct NodeResponse {
    pub node: NodeInfo,
    pub response: Result<response::Response, crate::crypto::Error>,
    pub height: u64,
}

#[async_trait]
/// Test interface for chasm for unit tests
pub trait TestChasm {

    /// Return number of nodes in cluster
    fn len(&self) -> usize;

    /// Return expected height chain as read from cluster (basically cluster should determine what the height is)
    fn height(&self) -> u64;

    // Get address information for a node
    fn get_node_info_for(&self, participant: NonZeroU32) -> NodeInfo;

    /// Return a list of all participants
    fn participants_all(&self) -> Option< Vec<NonZeroU32> > {
        Some((0 .. self.len()).map(|x| NonZeroU32::new(x as u32 + 1).unwrap()).collect())
    }

    /// Return participants for given subset
    fn participants_some(&self, participants: &[u32]) -> Option< Vec<NonZeroU32> > {
        Some(participants.into_iter().map(|x| NonZeroU32::new(*x).unwrap()).collect())
    }

    /// Return a threshold using all participants in cluster
    fn threshold_all(&self) -> Option<request::ThresholdMeta> {
        let participants = self.participants_all().unwrap();
        Some(request::ThresholdMeta {
            participants: (0 .. self.len()).map(|x| participants[x]).collect(),
            threshold: NonZeroU32::new(self.len() as u32).unwrap(),
        })
    }
    /// Return a threshold using some participants in cluster
    fn threshold_some(&self, threshold: u32) -> Option<request::ThresholdMeta> {
        let participants = self.participants_all().unwrap();
        Some(request::ThresholdMeta {
            participants: (0 .. self.len()).map(|x| participants[x]).collect(),
            threshold: NonZeroU32::new(threshold).unwrap(),
        })
    }

    /// Rend a chasm request to all nodes and get response from all nodes back.
    async fn send_recv(&mut self, req: request::Request) -> Vec<NodeResponse>;

    /// Start the cluster
    async fn start(&mut self);
    /// Stop the cluster
    async fn stop(&mut self);
    /// Return true if the cluster is running
    fn has_started(&self) -> bool;
    /// Stop a specific node
    async fn stop_node(&mut self, participant: u32);
}

#[async_trait]
pub trait TestChasmWithQuerying<Q: QueryClient + Send + 'static> {
    // Start cluster with method to query contracts on it's own.
    async fn start_with_cosmos_dispatch(&mut self, query_client: Q);
    /// Have chasm process requests on it's own (i.e. query contract) and return responses.  Use input timeout.
    async fn process_requests_for(&mut self, timeout: Duration) -> Vec<NodeResponse>;
    /// Use default timeout.
    async fn process_requests(&mut self) -> Vec<NodeResponse>;
}

// A "dumb" test reference implementation of chasm
type KeyTriplet = (String, crypto::SecretKey, Option<request::ThresholdMeta>);
pub struct ChasmCluster {
    instances: u32,
    timeout: Duration,
    block_height: u64,
    started: bool,
    stopped_nodes: Vec<u32>,
    // <(key-name, key, threshold)>
    keys: Vec<KeyTriplet>,
    heights_last_transmitted: Vec<u64>,
}

pub struct ChasmClusterWithQuerying<Q: QueryClient + Send> {
    cluster: ChasmCluster,
    query_client: Option<Q>,
}
unsafe impl Send for ChasmCluster{}
unsafe impl Sync for ChasmCluster{}

unsafe impl<Q: QueryClient + Send> Send for ChasmClusterWithQuerying<Q>{}
unsafe impl<Q: QueryClient + Send> Sync for ChasmClusterWithQuerying<Q>{}

impl ChasmCluster {
    pub fn new(instances: u32, timeout: Duration) -> Self {
        let block_height = 0;
        let heights_last_transmitted = vec![block_height; instances as usize];
        let started = false;
        let stopped_nodes = vec![];
        let keys = vec![];
        Self{instances, timeout, block_height, started, stopped_nodes, keys, heights_last_transmitted}
    }

    async fn send_recv_for(&mut self, req: request::Request, participant: NonZeroU32) -> crypto::Result<response::Response> {
        let is_first =  participant == self.participants_all().unwrap()[0];
        if self.stopped_nodes.contains(&participant.get()) {
            // disconnect timeout error
            println!("timeout for {}", participant.get());
            return Err(crypto::Error::TimedOut(vec![participant.get()]));
        }
        let res = match &req {
            request::Request::GenerateKey(req) => {
                let mut re: api::Re = Default::default();
                re.name = req.re.name.clone();

                let opts: Vec<&KeyTriplet> = (&self.keys).into_iter().filter(|key| key.0 == req.meta.name).collect();
                if opts.len() > 0 && is_first {
                    return Err(crypto::Error::ExistingKey);
                }
                let key = if is_first {
                    let key = crypto::SecretKey::new(req.meta.algorithm);
                    self.keys.push((req.meta.name.clone(), key, req.meta.threshold.clone()));
                    &self.keys.last().as_ref().unwrap().1
                } else {
                    &opts[0].1
                };
                let public_key = key.public().unwrap();
                Ok(response::Response::GenerateKey(response::GenerateKey{
                    re,
                    public_key: public_key.marshal(),
                }))
            },
            request::Request::Sign(req) => {
                let opts: Vec<&KeyTriplet> = (&self.keys).into_iter().filter(|key| key.0 == req.meta.key ).collect();
                if opts.len() == 0 {
                    return Err(crypto::Error::UnknownKey);
                } 
                let (_key_name, key, key_threshold) = &opts[0];
                let mut re: api::Re = Default::default();
                re.name = req.re.name.clone();

                if req.meta.participants.is_some() {
                    let signer_participants = req.meta.participants.as_ref().unwrap();
                    if req.meta.participants.as_ref().unwrap().len() > (self.instances as usize - self.stopped_nodes.len()) {
                        return Err(crypto::Error::TimedOut(vec![participant.get()]))
                    }
                    if key_threshold.is_some() {
                        let quorom: Set<_> = key_threshold.clone().unwrap().participants.iter().copied().collect();
                        let quorom_min = key_threshold.clone().unwrap().threshold.get() as usize;
                        if quorom_min > signer_participants.len() {
                            return Err(crypto::Error::Frost(frost::Error::UnqualifiedQuorum(quorom)))
                        }
                    }
                    if !signer_participants.contains(&participant) {
                        return Err(crypto::Error::Frost(frost::Error::InvalidParticipant))
                    }
                } 

                // don't have enough nodes online for this -- timeout
                let sig = match &req.meta.data {
                    request::Data::Message(msg) => key.sign(msg).unwrap(),
                    request::Data::Digest(digest) => key.sign_digest(digest).unwrap(),
                };
                Ok(response::Response::Sign(response::Sign{
                    re,
                    signature: sig.serialize(req.meta.format).unwrap(),
                }))                        

            }
            _ => unimplemented!(),
        };
        return res;
    }


}

impl <Q: QueryClient + Send> ChasmClusterWithQuerying<Q> {
    pub fn new(instances: u32, timeout: Duration) -> Self {
        let cluster = ChasmCluster::new(instances, timeout);
        let query_client = None;
        Self{query_client, cluster}
    }
}

#[async_trait::async_trait]
impl<Q: QueryClient + Send + 'static + Sync> TestChasmWithQuerying<Q> for ChasmClusterWithQuerying<Q> {
    async fn start_with_cosmos_dispatch(&mut self, query_client: Q) {
        self.query_client = Some(query_client);
        self.start().await;
    }
    // process requests using a different timeout than is default.
    async fn process_requests_for(&mut self, timeout: Duration) -> Vec<NodeResponse> {
        let current_timeout = self.cluster.timeout;
        self.cluster.timeout = timeout;
        let res = self.process_requests().await;
        self.cluster.timeout = current_timeout;
        return res;
    }
    async fn process_requests(&mut self) -> Vec<NodeResponse> {
        let mut responses: Vec<NodeResponse> = vec![];
        let pending_signs;
        let pending_gen;
        self.cluster.block_height += 1;
        if let Some(query_client) = self.query_client.as_mut() {
            pending_signs = query_client.pending_generate_keys().await.unwrap().0;
            pending_gen = query_client.pending_signs().await.unwrap().0;
        } else {
            panic!("must set a query client")
        }
        for p in pending_signs {
            let mut re: api::Re = Default::default();
            re.name = p.re.name.clone();
            let res = self.send_recv(request::Request::GenerateKey(p)).await;
            for mut r in res {
                if r.response.is_err() {
                    r.response = Ok(response::Response::FailedRequest(response::FailedRequest{
                        re: re.clone(),
                        error: r.response.err().unwrap(),
                    }))
                }

                responses.push(r);
            }
        }
        for p in pending_gen {
            let mut re: api::Re = Default::default();
            re.name = p.re.name.clone();
            let res = self.send_recv(request::Request::Sign(p)).await;
            for mut r in res {
                if r.response.is_err() {
                    r.response = Ok(response::Response::FailedRequest(response::FailedRequest{
                        re: re.clone(),
                        error: r.response.err().unwrap(),
                    }))
                }
                responses.push(r);
            }
        }

        for i in self.participants_all().unwrap() {
            for res in &responses {
                if res.node.participant == i {
                    self.cluster.heights_last_transmitted[i.get() as usize - 1] = self.cluster.block_height;
                }
            }
        }
        for i in self.participants_all().unwrap() {
            let last_height = self.cluster.heights_last_transmitted[i.get() as usize - 1];
            if self.cluster.block_height >= HEARTBEAT_BLOCK_PERIOD {
                if (self.cluster.block_height - HEARTBEAT_BLOCK_PERIOD) >= last_height {
                    // time for this "node" to send a heartbeat
                    self.cluster.heights_last_transmitted[i.get() as usize - 1] = self.cluster.block_height;
                    responses.push(
                        NodeResponse{
                            height: self.cluster.block_height,
                            node: self.get_node_info_for(i),
                            response: Ok(response::Response::Heartbeat(response::Heartbeat{
                                re: Default::default(),
                            }))                        
                        }
                    );
                }
            }
        }

        responses
    }
}

#[async_trait::async_trait]
impl<Q: QueryClient + Send + 'static + Sync> TestChasm for ChasmClusterWithQuerying<Q> {
    fn len(&self) -> usize { self.cluster.len() }
    fn height(&self) -> u64 { self.cluster.height() }
    fn get_node_info_for(&self, participant: NonZeroU32) -> NodeInfo { self.cluster.get_node_info_for(participant) }
    async fn send_recv(&mut self, req: request::Request) -> Vec<NodeResponse> { self.cluster.send_recv(req).await }
    async fn start(&mut self) { self.cluster.start().await }
    async fn stop(&mut self) { self.cluster.stop().await }
    async fn stop_node(&mut self, participant: u32) { self.stop_node(participant).await }
    fn has_started(&self) -> bool { self.cluster.has_started() }
}

#[async_trait::async_trait]
impl TestChasm for ChasmCluster {
    fn len(&self) -> usize {
        self.instances as usize
    }
    fn height(&self) -> u64 {
        self.block_height
    }
    fn get_node_info_for(&self, participant: NonZeroU32) -> NodeInfo {
        let mut account_id_raw = [0; 20];
        let participant_bytes = participant.get().to_be_bytes();
        for (i,byte) in participant_bytes.into_iter().enumerate() {
            account_id_raw[i] = byte;
        }
        let account_id = cosmrs::AccountId::new("wasm", &account_id_raw).unwrap();
        NodeInfo { participant: participant, account_id: account_id }
    }
    async fn send_recv(&mut self, req: request::Request) -> Vec<NodeResponse> {
        if !self.started {
            panic!("cannot send_recv unless we've started the cluster");
        }
        let mut responses: Vec<NodeResponse> = Default::default();
        for i in self.participants_all().unwrap() {
            println!("stopped nodes = {:?}", &self.stopped_nodes);
            let res = self.send_recv_for(req.clone(), i).await;
            responses.push(NodeResponse{
                height: self.block_height,
                node: self.get_node_info_for(i),
                response: res,
            });
        }
        responses
    }
    async fn start(&mut self) {
        self.started = true;
        self.stopped_nodes = vec![];
    }

    fn has_started(&self) -> bool {
        self.started
    }
    async fn stop(&mut self) {
        self.started = false;
    }

    async fn stop_node(&mut self, participant: u32) {
        self.stopped_nodes.push(participant);
    }

}

