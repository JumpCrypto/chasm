/// AccessTypeParam
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccessTypeParam {
    #[prost(enumeration="AccessType", tag="1")]
    pub value: i32,
}
/// AccessConfig access control type.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccessConfig {
    #[prost(enumeration="AccessType", tag="1")]
    pub permission: i32,
    #[prost(string, tag="2")]
    pub address: ::prost::alloc::string::String,
}
/// Params defines the set of wasm parameters.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Params {
    #[prost(message, optional, tag="1")]
    pub code_upload_access: ::core::option::Option<AccessConfig>,
    #[prost(enumeration="AccessType", tag="2")]
    pub instantiate_default_permission: i32,
}
/// CodeInfo is data for the uploaded contract WASM code
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CodeInfo {
    /// CodeHash is the unique identifier created by wasmvm
    #[prost(bytes="vec", tag="1")]
    pub code_hash: ::prost::alloc::vec::Vec<u8>,
    /// Creator address who initially stored the code
    #[prost(string, tag="2")]
    pub creator: ::prost::alloc::string::String,
    /// InstantiateConfig access control to apply on contract creation, optional
    #[prost(message, optional, tag="5")]
    pub instantiate_config: ::core::option::Option<AccessConfig>,
}
/// ContractInfo stores a WASM contract instance
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ContractInfo {
    /// CodeID is the reference to the stored Wasm code
    #[prost(uint64, tag="1")]
    pub code_id: u64,
    /// Creator address who initially instantiated the contract
    #[prost(string, tag="2")]
    pub creator: ::prost::alloc::string::String,
    /// Admin is an optional address that can execute migrations
    #[prost(string, tag="3")]
    pub admin: ::prost::alloc::string::String,
    /// Label is optional metadata to be stored with a contract instance.
    #[prost(string, tag="4")]
    pub label: ::prost::alloc::string::String,
    /// Created Tx position when the contract was instantiated.
    /// This data should kept internal and not be exposed via query results. Just
    /// use for sorting
    #[prost(message, optional, tag="5")]
    pub created: ::core::option::Option<AbsoluteTxPosition>,
    #[prost(string, tag="6")]
    pub ibc_port_id: ::prost::alloc::string::String,
    /// Extension is an extension point to store custom metadata within the
    /// persistence model.
    #[prost(message, optional, tag="7")]
    pub extension: ::core::option::Option<::prost_types::Any>,
}
/// ContractCodeHistoryEntry metadata to a contract.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ContractCodeHistoryEntry {
    #[prost(enumeration="ContractCodeHistoryOperationType", tag="1")]
    pub operation: i32,
    /// CodeID is the reference to the stored WASM code
    #[prost(uint64, tag="2")]
    pub code_id: u64,
    /// Updated Tx position when the operation was executed.
    #[prost(message, optional, tag="3")]
    pub updated: ::core::option::Option<AbsoluteTxPosition>,
    #[prost(bytes="vec", tag="4")]
    pub msg: ::prost::alloc::vec::Vec<u8>,
}
/// AbsoluteTxPosition is a unique transaction position that allows for global
/// ordering of transactions.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AbsoluteTxPosition {
    /// BlockHeight is the block the contract was created at
    #[prost(uint64, tag="1")]
    pub block_height: u64,
    /// TxIndex is a monotonic counter within the block (actual transaction index,
    /// or gas consumed)
    #[prost(uint64, tag="2")]
    pub tx_index: u64,
}
/// Model is a struct that holds a KV pair
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Model {
    /// hex-encode key to read it better (this is often ascii)
    #[prost(bytes="vec", tag="1")]
    pub key: ::prost::alloc::vec::Vec<u8>,
    /// base64-encode raw value
    #[prost(bytes="vec", tag="2")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
/// AccessType permission types
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum AccessType {
    /// AccessTypeUnspecified placeholder for empty value
    Unspecified = 0,
    /// AccessTypeNobody forbidden
    Nobody = 1,
    /// AccessTypeOnlyAddress restricted to an address
    OnlyAddress = 2,
    /// AccessTypeEverybody unrestricted
    Everybody = 3,
}
/// ContractCodeHistoryOperationType actions that caused a code change
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ContractCodeHistoryOperationType {
    /// ContractCodeHistoryOperationTypeUnspecified placeholder for empty value
    Unspecified = 0,
    /// ContractCodeHistoryOperationTypeInit on chain contract instantiation
    Init = 1,
    /// ContractCodeHistoryOperationTypeMigrate code migration
    Migrate = 2,
    /// ContractCodeHistoryOperationTypeGenesis based on genesis data
    Genesis = 3,
}
/// QueryContractInfoRequest is the request type for the Query/ContractInfo RPC
/// method
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryContractInfoRequest {
    /// address is the address of the contract to query
    #[prost(string, tag="1")]
    pub address: ::prost::alloc::string::String,
}
/// QueryContractInfoResponse is the response type for the Query/ContractInfo RPC
/// method
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryContractInfoResponse {
    /// address is the address of the contract
    #[prost(string, tag="1")]
    pub address: ::prost::alloc::string::String,
    #[prost(message, optional, tag="2")]
    pub contract_info: ::core::option::Option<ContractInfo>,
}
/// QueryContractHistoryRequest is the request type for the Query/ContractHistory
/// RPC method
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryContractHistoryRequest {
    /// address is the address of the contract to query
    #[prost(string, tag="1")]
    pub address: ::prost::alloc::string::String,
    /// pagination defines an optional pagination for the request.
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageRequest>,
}
/// QueryContractHistoryResponse is the response type for the
/// Query/ContractHistory RPC method
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryContractHistoryResponse {
    #[prost(message, repeated, tag="1")]
    pub entries: ::prost::alloc::vec::Vec<ContractCodeHistoryEntry>,
    /// pagination defines the pagination in the response.
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageResponse>,
}
/// QueryContractsByCodeRequest is the request type for the Query/ContractsByCode
/// RPC method
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryContractsByCodeRequest {
    /// grpc-gateway_out does not support Go style CodID
    #[prost(uint64, tag="1")]
    pub code_id: u64,
    /// pagination defines an optional pagination for the request.
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageRequest>,
}
/// QueryContractsByCodeResponse is the response type for the
/// Query/ContractsByCode RPC method
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryContractsByCodeResponse {
    /// contracts are a set of contract addresses
    #[prost(string, repeated, tag="1")]
    pub contracts: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// pagination defines the pagination in the response.
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageResponse>,
}
/// QueryAllContractStateRequest is the request type for the
/// Query/AllContractState RPC method
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryAllContractStateRequest {
    /// address is the address of the contract
    #[prost(string, tag="1")]
    pub address: ::prost::alloc::string::String,
    /// pagination defines an optional pagination for the request.
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageRequest>,
}
/// QueryAllContractStateResponse is the response type for the
/// Query/AllContractState RPC method
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryAllContractStateResponse {
    #[prost(message, repeated, tag="1")]
    pub models: ::prost::alloc::vec::Vec<Model>,
    /// pagination defines the pagination in the response.
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageResponse>,
}
/// QueryRawContractStateRequest is the request type for the
/// Query/RawContractState RPC method
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryRawContractStateRequest {
    /// address is the address of the contract
    #[prost(string, tag="1")]
    pub address: ::prost::alloc::string::String,
    #[prost(bytes="vec", tag="2")]
    pub query_data: ::prost::alloc::vec::Vec<u8>,
}
/// QueryRawContractStateResponse is the response type for the
/// Query/RawContractState RPC method
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryRawContractStateResponse {
    /// Data contains the raw store data
    #[prost(bytes="vec", tag="1")]
    pub data: ::prost::alloc::vec::Vec<u8>,
}
/// QuerySmartContractStateRequest is the request type for the
/// Query/SmartContractState RPC method
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QuerySmartContractStateRequest {
    /// address is the address of the contract
    #[prost(string, tag="1")]
    pub address: ::prost::alloc::string::String,
    /// QueryData contains the query data passed to the contract
    #[prost(bytes="vec", tag="2")]
    pub query_data: ::prost::alloc::vec::Vec<u8>,
}
/// QuerySmartContractStateResponse is the response type for the
/// Query/SmartContractState RPC method
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QuerySmartContractStateResponse {
    /// Data contains the json data returned from the smart contract
    #[prost(bytes="vec", tag="1")]
    pub data: ::prost::alloc::vec::Vec<u8>,
}
/// QueryCodeRequest is the request type for the Query/Code RPC method
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryCodeRequest {
    /// grpc-gateway_out does not support Go style CodID
    #[prost(uint64, tag="1")]
    pub code_id: u64,
}
/// CodeInfoResponse contains code meta data from CodeInfo
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CodeInfoResponse {
    /// id for legacy support
    #[prost(uint64, tag="1")]
    pub code_id: u64,
    #[prost(string, tag="2")]
    pub creator: ::prost::alloc::string::String,
    #[prost(bytes="vec", tag="3")]
    pub data_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag="6")]
    pub instantiate_permission: ::core::option::Option<AccessConfig>,
}
/// QueryCodeResponse is the response type for the Query/Code RPC method
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryCodeResponse {
    #[prost(message, optional, tag="1")]
    pub code_info: ::core::option::Option<CodeInfoResponse>,
    #[prost(bytes="vec", tag="2")]
    pub data: ::prost::alloc::vec::Vec<u8>,
}
/// QueryCodesRequest is the request type for the Query/Codes RPC method
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryCodesRequest {
    /// pagination defines an optional pagination for the request.
    #[prost(message, optional, tag="1")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageRequest>,
}
/// QueryCodesResponse is the response type for the Query/Codes RPC method
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryCodesResponse {
    #[prost(message, repeated, tag="1")]
    pub code_infos: ::prost::alloc::vec::Vec<CodeInfoResponse>,
    /// pagination defines the pagination in the response.
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageResponse>,
}
/// QueryPinnedCodesRequest is the request type for the Query/PinnedCodes
/// RPC method
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryPinnedCodesRequest {
    /// pagination defines an optional pagination for the request.
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageRequest>,
}
/// QueryPinnedCodesResponse is the response type for the
/// Query/PinnedCodes RPC method
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryPinnedCodesResponse {
    #[prost(uint64, repeated, packed="false", tag="1")]
    pub code_ids: ::prost::alloc::vec::Vec<u64>,
    /// pagination defines the pagination in the response.
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageResponse>,
}
/// MsgStoreCode submit Wasm code to the system
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgStoreCode {
    /// Sender is the that actor that signed the messages
    #[prost(string, tag="1")]
    pub sender: ::prost::alloc::string::String,
    /// WASMByteCode can be raw or gzip compressed
    #[prost(bytes="vec", tag="2")]
    pub wasm_byte_code: ::prost::alloc::vec::Vec<u8>,
    /// InstantiatePermission access control to apply on contract creation,
    /// optional
    #[prost(message, optional, tag="5")]
    pub instantiate_permission: ::core::option::Option<AccessConfig>,
}
/// MsgStoreCodeResponse returns store result data.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgStoreCodeResponse {
    /// CodeID is the reference to the stored WASM code
    #[prost(uint64, tag="1")]
    pub code_id: u64,
}
/// MsgInstantiateContract create a new smart contract instance for the given
/// code id.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgInstantiateContract {
    /// Sender is the that actor that signed the messages
    #[prost(string, tag="1")]
    pub sender: ::prost::alloc::string::String,
    /// Admin is an optional address that can execute migrations
    #[prost(string, tag="2")]
    pub admin: ::prost::alloc::string::String,
    /// CodeID is the reference to the stored WASM code
    #[prost(uint64, tag="3")]
    pub code_id: u64,
    /// Label is optional metadata to be stored with a contract instance.
    #[prost(string, tag="4")]
    pub label: ::prost::alloc::string::String,
    /// Msg json encoded message to be passed to the contract on instantiation
    #[prost(bytes="vec", tag="5")]
    pub msg: ::prost::alloc::vec::Vec<u8>,
    /// Funds coins that are transferred to the contract on instantiation
    #[prost(message, repeated, tag="6")]
    pub funds: ::prost::alloc::vec::Vec<super::super::super::cosmos::base::v1beta1::Coin>,
}
/// MsgInstantiateContractResponse return instantiation result data
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgInstantiateContractResponse {
    /// Address is the bech32 address of the new contract instance.
    #[prost(string, tag="1")]
    pub address: ::prost::alloc::string::String,
    /// Data contains base64-encoded bytes to returned from the contract
    #[prost(bytes="vec", tag="2")]
    pub data: ::prost::alloc::vec::Vec<u8>,
}
/// MsgExecuteContract submits the given message data to a smart contract
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgExecuteContract {
    /// Sender is the that actor that signed the messages
    #[prost(string, tag="1")]
    pub sender: ::prost::alloc::string::String,
    /// Contract is the address of the smart contract
    #[prost(string, tag="2")]
    pub contract: ::prost::alloc::string::String,
    /// Msg json encoded message to be passed to the contract
    #[prost(bytes="vec", tag="3")]
    pub msg: ::prost::alloc::vec::Vec<u8>,
    /// Funds coins that are transferred to the contract on execution
    #[prost(message, repeated, tag="5")]
    pub funds: ::prost::alloc::vec::Vec<super::super::super::cosmos::base::v1beta1::Coin>,
}
/// MsgExecuteContractResponse returns execution result data.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgExecuteContractResponse {
    /// Data contains base64-encoded bytes to returned from the contract
    #[prost(bytes="vec", tag="1")]
    pub data: ::prost::alloc::vec::Vec<u8>,
}
/// MsgMigrateContract runs a code upgrade/ downgrade for a smart contract
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgMigrateContract {
    /// Sender is the that actor that signed the messages
    #[prost(string, tag="1")]
    pub sender: ::prost::alloc::string::String,
    /// Contract is the address of the smart contract
    #[prost(string, tag="2")]
    pub contract: ::prost::alloc::string::String,
    /// CodeID references the new WASM code
    #[prost(uint64, tag="3")]
    pub code_id: u64,
    /// Msg json encoded message to be passed to the contract on migration
    #[prost(bytes="vec", tag="4")]
    pub msg: ::prost::alloc::vec::Vec<u8>,
}
/// MsgMigrateContractResponse returns contract migration result data.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgMigrateContractResponse {
    /// Data contains same raw bytes returned as data from the wasm contract.
    /// (May be empty)
    #[prost(bytes="vec", tag="1")]
    pub data: ::prost::alloc::vec::Vec<u8>,
}
/// MsgUpdateAdmin sets a new admin for a smart contract
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgUpdateAdmin {
    /// Sender is the that actor that signed the messages
    #[prost(string, tag="1")]
    pub sender: ::prost::alloc::string::String,
    /// NewAdmin address to be set
    #[prost(string, tag="2")]
    pub new_admin: ::prost::alloc::string::String,
    /// Contract is the address of the smart contract
    #[prost(string, tag="3")]
    pub contract: ::prost::alloc::string::String,
}
/// MsgUpdateAdminResponse returns empty data
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgUpdateAdminResponse {
}
/// MsgClearAdmin removes any admin stored for a smart contract
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgClearAdmin {
    /// Sender is the that actor that signed the messages
    #[prost(string, tag="1")]
    pub sender: ::prost::alloc::string::String,
    /// Contract is the address of the smart contract
    #[prost(string, tag="3")]
    pub contract: ::prost::alloc::string::String,
}
/// MsgClearAdminResponse returns empty data
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgClearAdminResponse {
}
