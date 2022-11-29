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
