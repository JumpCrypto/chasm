/// Metadata for each request and response
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Re {
    /// Request or remote-procedure *call* ID/name.
    /// Must be globally unique for new requests - easiest to use UUID4
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
    /// seconds since UNIX epoch (e.g. time.Now().Unix() in Go)
    #[prost(int64, tag="2")]
    pub at: i64,
}
/// Cluster defines a chasm cluster. It is mostly informational.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Cluster {
    #[prost(string, tag="2")]
    pub name: ::prost::alloc::string::String,
    #[prost(enumeration="Algorithm", repeated, tag="4")]
    pub algorithms: ::prost::alloc::vec::Vec<i32>,
    /// leave empty for non-networked clusters
    /// numbers must be >= 1, but don't have type system support
    #[prost(uint32, repeated, tag="5")]
    pub participants: ::prost::alloc::vec::Vec<u32>,
    /// threshold used for keygen, missing/zero interpreted as 1
    #[prost(uint32, tag="6")]
    pub threshold: u32,
}
/// Metadata describing a key
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeyMeta {
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub cluster: ::prost::alloc::string::String,
    #[prost(enumeration="Algorithm", tag="3")]
    pub algorithm: i32,
    #[prost(uint32, tag="4")]
    pub threshold: u32,
    #[prost(enumeration="PublicKeyFormat", tag="6")]
    pub format: i32,
    #[prost(uint32, repeated, tag="7")]
    pub participants: ::prost::alloc::vec::Vec<u32>,
}
/// Metadata describing a key
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChildMeta {
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub cluster: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub parent: ::prost::alloc::string::String,
    /// we don't really want to offer anything byte chain = [0u8; 32] 
    #[prost(uint32, tag="4")]
    pub child: u32,
    // bytes chain_code = ?; 

    #[prost(enumeration="PublicKeyFormat", tag="5")]
    pub format: i32,
}
/// Data defining a key
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeyData {
    #[prost(bytes="vec", tag="1")]
    pub public_key: ::prost::alloc::vec::Vec<u8>,
}
/// Brief history on when object was requested and actually created
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct When {
    #[prost(int64, tag="1")]
    pub requested_at: i64,
    #[prost(int64, tag="2")]
    pub responded_at: i64,
}
/// Core state object: cryptographic key that may be used.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Key {
    #[prost(message, optional, tag="1")]
    pub when: ::core::option::Option<When>,
    #[prost(message, optional, tag="2")]
    pub meta: ::core::option::Option<KeyMeta>,
    #[prost(message, optional, tag="3")]
    pub data: ::core::option::Option<KeyData>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PendingGenerateKey {
    #[prost(message, optional, tag="1")]
    pub re: ::core::option::Option<Re>,
    #[prost(message, optional, tag="2")]
    pub meta: ::core::option::Option<KeyMeta>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PendingDeriveChildKey {
    #[prost(message, optional, tag="1")]
    pub re: ::core::option::Option<Re>,
    #[prost(message, optional, tag="2")]
    pub meta: ::core::option::Option<ChildMeta>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WrappedKeyData {
    #[prost(string, tag="1")]
    pub wrapping_key: ::prost::alloc::string::String,
    #[prost(enumeration="SecretKeyFormat", tag="2")]
    pub format: i32,
    #[prost(bytes="vec", tag="3")]
    pub wrapped_key: ::prost::alloc::vec::Vec<u8>,
}
// message WrappedKey { 

//   KeyMeta meta = 1; 

//   WrappedKeyData wrapped_data = 2; 

// } 

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PendingUnwrapKey {
    #[prost(message, optional, tag="1")]
    pub re: ::core::option::Option<Re>,
    #[prost(message, optional, tag="2")]
    pub meta: ::core::option::Option<KeyMeta>,
    #[prost(message, optional, tag="3")]
    pub wrapped_data: ::core::option::Option<WrappedKeyData>,
}
/// NB: Would really like to model (data, prehashed) pair as
/// enum { Message(str), Digest(str) }, but alas, this is Go/Proto...
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignatureMeta {
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub cluster: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub key: ::prost::alloc::string::String,
    #[prost(bytes="vec", tag="4")]
    pub data: ::prost::alloc::vec::Vec<u8>,
    #[prost(bool, tag="5")]
    pub prehashed: bool,
    #[prost(enumeration="SignatureFormat", tag="6")]
    pub format: i32,
    #[prost(uint32, repeated, tag="7")]
    pub participants: ::prost::alloc::vec::Vec<u32>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignatureData {
    #[prost(bytes="vec", tag="1")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PendingSign {
    #[prost(message, optional, tag="1")]
    pub re: ::core::option::Option<Re>,
    #[prost(message, optional, tag="2")]
    pub meta: ::core::option::Option<SignatureMeta>,
}
/// Core state object: generated signature.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Signature {
    #[prost(message, optional, tag="1")]
    pub when: ::core::option::Option<When>,
    #[prost(message, optional, tag="2")]
    pub meta: ::core::option::Option<SignatureMeta>,
    #[prost(message, optional, tag="3")]
    pub data: ::core::option::Option<SignatureData>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FailedRequestData {
    #[prost(string, tag="1")]
    pub error: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FailedRequest {
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
    #[prost(message, optional, tag="2")]
    pub when: ::core::option::Option<When>,
    /// oneof request { 
    #[prost(message, optional, tag="3")]
    pub generate_key: ::core::option::Option<PendingGenerateKey>,
    #[prost(message, optional, tag="4")]
    pub unwrap_key: ::core::option::Option<PendingUnwrapKey>,
    #[prost(message, optional, tag="5")]
    pub sign: ::core::option::Option<PendingSign>,
    /// } 
    #[prost(message, optional, tag="6")]
    pub data: ::core::option::Option<FailedRequestData>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Algorithm {
    AlgSecret = 0,
    AlgEd255 = 1,
    AlgK256 = 2,
    AlgP256 = 3,
    AlgX255 = 4,
    AlgRistretto255 = 5,
    AlgK256Taproot = 6,
}
// cf. <https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/>

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum PublicKeyFormat {
    /// Invalid choice. Be explicit!
    PkUndefined = 0,
    /// big-endian U256 X-coordinate, then big-endian U256 Y-coordinate
    /// the raw big-endian U256 secret number as 32 bytes
    PkRaw = 1,
    /// 0x02 or 0x03 depending on sign of Y-coordinate, then big-endian U256 X-coordinate
    /// Python cryptography calls this "CompressedPoint"
    PkCompressedPoint = 2,
    /// 0x04, then the same as PK_RAW
    /// Python cryptography calls this "UncompressedPoint"
    PkUncompressedPoint = 3,
    /// the UTF-8 string (e.g. `age1txvvuecr2fyypyuwhy867gghjvmju8h0jfdmu938yaegq6dsxdcsy7xk5p` for X255 age recipients), encoded as bytes
    PkAge = 4,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum SecretKeyFormat {
    /// Invalid choice. Be explicit!
    SkUndefined = 0,
    /// the raw U256 secret, as 32 big-endian bytes
    SkRaw = 1,
    /// PKCS8 v1 (RFC 5208)
    SkPkcs8 = 2,
    /// SK_SEC1 = 2;
    /// we don't currently do BIP32-ish things, this is just encoding a 32 byte secret in 24 words from the standard English language
    /// cf. e.g. <https://docs.rs/hkd32/0.6.0/hkd32/struct.KeyMaterial.html>
    SkPhrase = 3,
    /// example: AGE-SECRET-KEY-1HR479D3GGXAF0F9QGZU4KMZZXC7SHSURR5QWHC8ZN264RUKMPFGSMTH26K
    SkAge = 4,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum SignatureFormat {
    /// Invalid choice. Be explicit!
    SigUndefined = 0,
    /// First U256 r as 32 big-endian bytes, then U256 s as 32 big-endian bytes. 64 bytes.
    SigRaw = 1,
    /// The raw signature, followed by a "recovery byte". 65 bytes.
    SigRawWithRecovery = 2,
    /// DER-encoding of ASN.1 wrapping of `(r, s)`: SEQUENCE 0x30, length, INTEGER 0x02, length, r,...
    /// typically: `0x30 0x44 0x02 0x20 <r\[32\]> 0x02 0x20 <s\[32\]>` (70-71 bytes)
    SigDer = 3,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryClusterRequest {
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryClusterResponse {
    #[prost(message, optional, tag="1")]
    pub cluster: ::core::option::Option<Cluster>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryClustersRequest {
    #[prost(message, optional, tag="1")]
    pub pagination: ::core::option::Option<super::cosmos::base::query::v1beta1::PageRequest>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryClustersResponse {
    #[prost(message, repeated, tag="1")]
    pub clusters: ::prost::alloc::vec::Vec<Cluster>,
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::cosmos::base::query::v1beta1::PageResponse>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryKeyRequest {
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryKeyResponse {
    #[prost(message, optional, tag="1")]
    pub key: ::core::option::Option<Key>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryKeysRequest {
    #[prost(message, optional, tag="1")]
    pub pagination: ::core::option::Option<super::cosmos::base::query::v1beta1::PageRequest>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryKeysResponse {
    #[prost(message, repeated, tag="1")]
    pub keys: ::prost::alloc::vec::Vec<Key>,
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::cosmos::base::query::v1beta1::PageResponse>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QuerySignatureRequest {
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QuerySignatureResponse {
    #[prost(message, optional, tag="1")]
    pub signature: ::core::option::Option<Signature>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QuerySignaturesRequest {
    #[prost(message, optional, tag="1")]
    pub pagination: ::core::option::Option<super::cosmos::base::query::v1beta1::PageRequest>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QuerySignaturesResponse {
    #[prost(message, repeated, tag="1")]
    pub signatures: ::prost::alloc::vec::Vec<Signature>,
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::cosmos::base::query::v1beta1::PageResponse>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryPendingGenerateKeysRequest {
    #[prost(message, optional, tag="1")]
    pub pagination: ::core::option::Option<super::cosmos::base::query::v1beta1::PageRequest>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryPendingGenerateKeysResponse {
    #[prost(message, repeated, tag="1")]
    pub keys: ::prost::alloc::vec::Vec<PendingGenerateKey>,
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::cosmos::base::query::v1beta1::PageResponse>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryPendingDeriveChildKeysRequest {
    #[prost(message, optional, tag="1")]
    pub pagination: ::core::option::Option<super::cosmos::base::query::v1beta1::PageRequest>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryPendingDeriveChildKeysResponse {
    #[prost(message, repeated, tag="1")]
    pub childs: ::prost::alloc::vec::Vec<PendingDeriveChildKey>,
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::cosmos::base::query::v1beta1::PageResponse>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryPendingUnwrapKeysRequest {
    #[prost(message, optional, tag="1")]
    pub pagination: ::core::option::Option<super::cosmos::base::query::v1beta1::PageRequest>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryPendingUnwrapKeysResponse {
    #[prost(message, repeated, tag="1")]
    pub keys: ::prost::alloc::vec::Vec<PendingUnwrapKey>,
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::cosmos::base::query::v1beta1::PageResponse>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryPendingSignsRequest {
    #[prost(message, optional, tag="1")]
    pub pagination: ::core::option::Option<super::cosmos::base::query::v1beta1::PageRequest>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryPendingSignsResponse {
    #[prost(message, repeated, tag="1")]
    pub signatures: ::prost::alloc::vec::Vec<PendingSign>,
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::cosmos::base::query::v1beta1::PageResponse>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryFailedRequestsRequest {
    #[prost(message, optional, tag="1")]
    pub pagination: ::core::option::Option<super::cosmos::base::query::v1beta1::PageRequest>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryFailedRequestsResponse {
    #[prost(message, repeated, tag="1")]
    pub requests: ::prost::alloc::vec::Vec<FailedRequest>,
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::cosmos::base::query::v1beta1::PageResponse>,
}
/// Generated client implementations.
pub mod query_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Query defines the gRPC querier service.
    #[derive(Debug, Clone)]
    pub struct QueryClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl QueryClient<tonic::transport::Channel> {
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
    impl<T> QueryClient<T>
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
        ) -> QueryClient<InterceptedService<T, F>>
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
            QueryClient::new(InterceptedService::new(inner, interceptor))
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
        /// Queries a cluster by name.
        pub async fn cluster(
            &mut self,
            request: impl tonic::IntoRequest<super::QueryClusterRequest>,
        ) -> Result<tonic::Response<super::QueryClusterResponse>, tonic::Status> {
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
            let path = http::uri::PathAndQuery::from_static("/chasm.Query/Cluster");
            self.inner.unary(request.into_request(), path, codec).await
        }
        /// Queries a list of cluster items.
        pub async fn clusters(
            &mut self,
            request: impl tonic::IntoRequest<super::QueryClustersRequest>,
        ) -> Result<tonic::Response<super::QueryClustersResponse>, tonic::Status> {
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
            let path = http::uri::PathAndQuery::from_static("/chasm.Query/Clusters");
            self.inner.unary(request.into_request(), path, codec).await
        }
        /// Queries a key by name.
        pub async fn key(
            &mut self,
            request: impl tonic::IntoRequest<super::QueryKeyRequest>,
        ) -> Result<tonic::Response<super::QueryKeyResponse>, tonic::Status> {
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
            let path = http::uri::PathAndQuery::from_static("/chasm.Query/Key");
            self.inner.unary(request.into_request(), path, codec).await
        }
        /// Queries a list of key items.
        pub async fn keys(
            &mut self,
            request: impl tonic::IntoRequest<super::QueryKeysRequest>,
        ) -> Result<tonic::Response<super::QueryKeysResponse>, tonic::Status> {
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
            let path = http::uri::PathAndQuery::from_static("/chasm.Query/Keys");
            self.inner.unary(request.into_request(), path, codec).await
        }
        /// Queries a signature by name.
        pub async fn signature(
            &mut self,
            request: impl tonic::IntoRequest<super::QuerySignatureRequest>,
        ) -> Result<tonic::Response<super::QuerySignatureResponse>, tonic::Status> {
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
            let path = http::uri::PathAndQuery::from_static("/chasm.Query/Signature");
            self.inner.unary(request.into_request(), path, codec).await
        }
        /// Queries a list of signature items.
        pub async fn signatures(
            &mut self,
            request: impl tonic::IntoRequest<super::QuerySignaturesRequest>,
        ) -> Result<tonic::Response<super::QuerySignaturesResponse>, tonic::Status> {
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
            let path = http::uri::PathAndQuery::from_static("/chasm.Query/Signatures");
            self.inner.unary(request.into_request(), path, codec).await
        }
        /// Queries the list of pending key gen items.
        pub async fn pending_generate_keys(
            &mut self,
            request: impl tonic::IntoRequest<super::QueryPendingGenerateKeysRequest>,
        ) -> Result<
            tonic::Response<super::QueryPendingGenerateKeysResponse>,
            tonic::Status,
        > {
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
                "/chasm.Query/PendingGenerateKeys",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        /// Queries the list of pending key gen items.
        pub async fn pending_derive_child_keys(
            &mut self,
            request: impl tonic::IntoRequest<super::QueryPendingDeriveChildKeysRequest>,
        ) -> Result<
            tonic::Response<super::QueryPendingDeriveChildKeysResponse>,
            tonic::Status,
        > {
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
                "/chasm.Query/PendingDeriveChildKeys",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        /// Queries the list of pending key unwrap items.
        pub async fn pending_unwrap_keys(
            &mut self,
            request: impl tonic::IntoRequest<super::QueryPendingUnwrapKeysRequest>,
        ) -> Result<
            tonic::Response<super::QueryPendingUnwrapKeysResponse>,
            tonic::Status,
        > {
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
                "/chasm.Query/PendingUnwrapKeys",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        /// Queries the list of pending sign items.
        pub async fn pending_signs(
            &mut self,
            request: impl tonic::IntoRequest<super::QueryPendingSignsRequest>,
        ) -> Result<tonic::Response<super::QueryPendingSignsResponse>, tonic::Status> {
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
            let path = http::uri::PathAndQuery::from_static("/chasm.Query/PendingSigns");
            self.inner.unary(request.into_request(), path, codec).await
        }
        /// Queries the list of failed requests
        pub async fn failed_requests(
            &mut self,
            request: impl tonic::IntoRequest<super::QueryFailedRequestsRequest>,
        ) -> Result<tonic::Response<super::QueryFailedRequestsResponse>, tonic::Status> {
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
                "/chasm.Query/FailedRequests",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgRegisterCluster {
    #[prost(string, tag="1")]
    pub registrant: ::prost::alloc::string::String,
    #[prost(message, optional, tag="2")]
    pub re: ::core::option::Option<Re>,
    #[prost(message, optional, tag="3")]
    pub cluster: ::core::option::Option<Cluster>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgRegisterClusterResponse {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgGenerateKey {
    #[prost(string, tag="1")]
    pub requestor: ::prost::alloc::string::String,
    #[prost(message, optional, tag="2")]
    pub request: ::core::option::Option<PendingGenerateKey>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgGenerateKeyResponse {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgGeneratedKey {
    #[prost(string, tag="1")]
    pub responder: ::prost::alloc::string::String,
    #[prost(message, optional, tag="2")]
    pub re: ::core::option::Option<Re>,
    #[prost(message, optional, tag="3")]
    pub data: ::core::option::Option<KeyData>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgGeneratedKeyResponse {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgDeriveChildKey {
    #[prost(string, tag="1")]
    pub requestor: ::prost::alloc::string::String,
    #[prost(message, optional, tag="2")]
    pub request: ::core::option::Option<PendingDeriveChildKey>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgDeriveChildKeyResponse {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgDerivedChildKey {
    #[prost(string, tag="1")]
    pub responder: ::prost::alloc::string::String,
    #[prost(message, optional, tag="2")]
    pub re: ::core::option::Option<Re>,
    #[prost(message, optional, tag="3")]
    pub data: ::core::option::Option<KeyData>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgDerivedChildKeyResponse {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgUnwrapKey {
    #[prost(string, tag="1")]
    pub requestor: ::prost::alloc::string::String,
    #[prost(message, optional, tag="2")]
    pub request: ::core::option::Option<PendingUnwrapKey>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgUnwrapKeyResponse {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgUnwrappedKey {
    #[prost(string, tag="1")]
    pub responder: ::prost::alloc::string::String,
    #[prost(message, optional, tag="2")]
    pub re: ::core::option::Option<Re>,
    #[prost(message, optional, tag="3")]
    pub data: ::core::option::Option<KeyData>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgUnwrappedKeyResponse {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgSign {
    #[prost(string, tag="1")]
    pub requestor: ::prost::alloc::string::String,
    #[prost(message, optional, tag="2")]
    pub request: ::core::option::Option<PendingSign>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgSignResponse {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgSigned {
    #[prost(string, tag="1")]
    pub responder: ::prost::alloc::string::String,
    #[prost(message, optional, tag="2")]
    pub re: ::core::option::Option<Re>,
    #[prost(message, optional, tag="3")]
    pub data: ::core::option::Option<SignatureData>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgSignedResponse {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgFailedRequest {
    #[prost(string, tag="1")]
    pub responder: ::prost::alloc::string::String,
    #[prost(message, optional, tag="2")]
    pub re: ::core::option::Option<Re>,
    #[prost(message, optional, tag="3")]
    pub data: ::core::option::Option<FailedRequestData>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgFailedRequestResponse {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgHeartbeat {
    #[prost(string, tag="1")]
    pub responder: ::prost::alloc::string::String,
    #[prost(message, optional, tag="2")]
    pub re: ::core::option::Option<Re>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgHeartbeatResponse {
}
/// Generated client implementations.
pub mod msg_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Msg defines the Msg service.
    /// TODO: Can we count on the "returns" always being `google.protobuf.Empty`?
    #[derive(Debug, Clone)]
    pub struct MsgClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl MsgClient<tonic::transport::Channel> {
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
    impl<T> MsgClient<T>
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
        ) -> MsgClient<InterceptedService<T, F>>
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
            MsgClient::new(InterceptedService::new(inner, interceptor))
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
        pub async fn register_cluster(
            &mut self,
            request: impl tonic::IntoRequest<super::MsgRegisterCluster>,
        ) -> Result<tonic::Response<super::MsgRegisterClusterResponse>, tonic::Status> {
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
                "/chasm.Msg/RegisterCluster",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn generate_key(
            &mut self,
            request: impl tonic::IntoRequest<super::MsgGenerateKey>,
        ) -> Result<tonic::Response<super::MsgGenerateKeyResponse>, tonic::Status> {
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
            let path = http::uri::PathAndQuery::from_static("/chasm.Msg/GenerateKey");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn generated_key(
            &mut self,
            request: impl tonic::IntoRequest<super::MsgGeneratedKey>,
        ) -> Result<tonic::Response<super::MsgGeneratedKeyResponse>, tonic::Status> {
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
            let path = http::uri::PathAndQuery::from_static("/chasm.Msg/GeneratedKey");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn derive_child_key(
            &mut self,
            request: impl tonic::IntoRequest<super::MsgDeriveChildKey>,
        ) -> Result<tonic::Response<super::MsgDeriveChildKeyResponse>, tonic::Status> {
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
            let path = http::uri::PathAndQuery::from_static("/chasm.Msg/DeriveChildKey");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn derived_child_key(
            &mut self,
            request: impl tonic::IntoRequest<super::MsgDerivedChildKey>,
        ) -> Result<tonic::Response<super::MsgDerivedChildKeyResponse>, tonic::Status> {
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
                "/chasm.Msg/DerivedChildKey",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn unwrap_key(
            &mut self,
            request: impl tonic::IntoRequest<super::MsgUnwrapKey>,
        ) -> Result<tonic::Response<super::MsgUnwrapKeyResponse>, tonic::Status> {
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
            let path = http::uri::PathAndQuery::from_static("/chasm.Msg/UnwrapKey");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn unwrapped_key(
            &mut self,
            request: impl tonic::IntoRequest<super::MsgUnwrappedKey>,
        ) -> Result<tonic::Response<super::MsgUnwrappedKeyResponse>, tonic::Status> {
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
            let path = http::uri::PathAndQuery::from_static("/chasm.Msg/UnwrappedKey");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn sign(
            &mut self,
            request: impl tonic::IntoRequest<super::MsgSign>,
        ) -> Result<tonic::Response<super::MsgSignResponse>, tonic::Status> {
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
            let path = http::uri::PathAndQuery::from_static("/chasm.Msg/Sign");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn signed(
            &mut self,
            request: impl tonic::IntoRequest<super::MsgSigned>,
        ) -> Result<tonic::Response<super::MsgSignedResponse>, tonic::Status> {
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
            let path = http::uri::PathAndQuery::from_static("/chasm.Msg/Signed");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn failed_request(
            &mut self,
            request: impl tonic::IntoRequest<super::MsgFailedRequest>,
        ) -> Result<tonic::Response<super::MsgFailedRequestResponse>, tonic::Status> {
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
            let path = http::uri::PathAndQuery::from_static("/chasm.Msg/FailedRequest");
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
}
