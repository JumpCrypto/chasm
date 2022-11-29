/// BroadcastTxRequest is the request type for the Service.BroadcastTxRequest
/// RPC method.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BroadcastTxRequest {
    /// tx_bytes is the raw transaction.
    #[prost(bytes="vec", tag="1")]
    pub tx_bytes: ::prost::alloc::vec::Vec<u8>,
    #[prost(enumeration="BroadcastMode", tag="2")]
    pub mode: i32,
}
/// BroadcastTxResponse is the response type for the
/// Service.BroadcastTx method.
///
/// tx_response is the queried TxResponses.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BroadcastTxResponse {
    /// cosmos.base.abci.v1beta1.TxResponse tx_response = 1; 
    #[prost(message, optional, tag="1")]
    pub tx_response: ::core::option::Option<TxResponse>,
}
/// TxResponse defines a structure containing relevant tx data and metadata. The
/// tags are stringified and the log is JSON decoded.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TxResponse {
    /// The block height
    #[prost(int64, tag="1")]
    pub height: i64,
    /// The transaction hash.
    #[prost(string, tag="2")]
    pub txhash: ::prost::alloc::string::String,
    /// Namespace for the Code
    #[prost(string, tag="3")]
    pub codespace: ::prost::alloc::string::String,
    /// Response code.
    #[prost(uint32, tag="4")]
    pub code: u32,
    /// Result bytes, if any.
    #[prost(string, tag="5")]
    pub data: ::prost::alloc::string::String,
    /// The output of the application's logger (raw string). May be
    /// non-deterministic.
    #[prost(string, tag="6")]
    pub raw_log: ::prost::alloc::string::String,
    /// The output of the application's logger (typed). May be non-deterministic.
    #[prost(message, repeated, tag="7")]
    pub logs: ::prost::alloc::vec::Vec<AbciMessageLog>,
    /// Additional information. May be non-deterministic.
    #[prost(string, tag="8")]
    pub info: ::prost::alloc::string::String,
    /// Amount of gas requested for transaction.
    #[prost(int64, tag="9")]
    pub gas_wanted: i64,
    /// Amount of gas consumed by transaction.
    #[prost(int64, tag="10")]
    pub gas_used: i64,
    /// The request transaction bytes.
    #[prost(message, optional, tag="11")]
    pub tx: ::core::option::Option<::prost_types::Any>,
    /// Time of the previous block. For heights > 1, it's the weighted median of
    /// the timestamps of the valid votes in the block.LastCommit. For height == 1,
    /// it's genesis time.
    #[prost(string, tag="12")]
    pub timestamp: ::prost::alloc::string::String,
}
/// ABCIMessageLog defines a structure containing an indexed tx ABCI message log.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AbciMessageLog {
    #[prost(uint32, tag="1")]
    pub msg_index: u32,
    #[prost(string, tag="2")]
    pub log: ::prost::alloc::string::String,
    /// Events contains a slice of Event objects that were emitted during some
    /// execution.
    #[prost(message, repeated, tag="3")]
    pub events: ::prost::alloc::vec::Vec<StringEvent>,
}
/// StringEvent defines en Event object wrapper where all the attributes
/// contain key/value pairs that are strings instead of raw bytes.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StringEvent {
    #[prost(string, tag="1")]
    pub r#type: ::prost::alloc::string::String,
    #[prost(message, repeated, tag="2")]
    pub attributes: ::prost::alloc::vec::Vec<Attribute>,
}
/// Attribute defines an attribute wrapper where the key and value are
/// strings instead of raw bytes.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Attribute {
    #[prost(string, tag="1")]
    pub key: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub value: ::prost::alloc::string::String,
}
/// BroadcastMode specifies the broadcast mode for the TxService.Broadcast RPC method.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum BroadcastMode {
    /// zero-value for mode ordering
    Unspecified = 0,
    /// BROADCAST_MODE_BLOCK defines a tx broadcasting mode where the client waits for
    /// the tx to be committed in a block.
    Block = 1,
    /// BROADCAST_MODE_SYNC defines a tx broadcasting mode where the client waits for
    /// a CheckTx execution response only.
    Sync = 2,
    /// BROADCAST_MODE_ASYNC defines a tx broadcasting mode where the client returns
    /// immediately.
    Async = 3,
}
/// Generated client implementations.
pub mod service_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Service defines a gRPC service for interacting with transactions.
    #[derive(Debug, Clone)]
    pub struct ServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl ServiceClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: std::convert::TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> ServiceClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> ServiceClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T::ResponseBody: Default,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
            >>::Error: Into<StdError> + Send + Sync,
        {
            ServiceClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress requests with `gzip`.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        #[must_use]
        pub fn send_gzip(mut self) -> Self {
            self.inner = self.inner.send_gzip();
            self
        }
        /// Enable decompressing responses with `gzip`.
        #[must_use]
        pub fn accept_gzip(mut self) -> Self {
            self.inner = self.inner.accept_gzip();
            self
        }
        /// BroadcastTx broadcast transaction.
        pub async fn broadcast_tx(
            &mut self,
            request: impl tonic::IntoRequest<super::BroadcastTxRequest>,
        ) -> Result<tonic::Response<super::BroadcastTxResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/cosmos.tx.v1beta1.Service/BroadcastTx",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
}
