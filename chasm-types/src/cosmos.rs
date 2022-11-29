
use async_trait::async_trait;
use crate::api::{request, response};
use crate::error::Error;

pub const HEARTBEAT_BLOCK_PERIOD: u64 = 60;
#[async_trait]
pub trait QueryClient : Clone {
    async fn connect(&mut self, grpc_endpoint: &str) -> Result<(), Error>;
    async fn pending_generate_keys(&mut self) -> Result<(Vec<request::GenerateKey>, Vec<response::FailedRequest>), tonic::Status>;
    async fn pending_derive_child_keys(&mut self) -> Result<(Vec<request::DeriveChildKey>, Vec<response::FailedRequest>), tonic::Status>;
    async fn pending_unwrap_keys(&mut self) -> Result<(Vec<request::UnwrapKey>, Vec<response::FailedRequest>), tonic::Status>;
    async fn pending_signs(&mut self) -> Result<(Vec<request::Sign>, Vec<response::FailedRequest>), tonic::Status>;
}
