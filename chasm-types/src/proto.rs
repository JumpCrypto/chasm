//! Protocol buffer types from the Cosmos x/chasm module.

#![allow(missing_docs)]
#![allow(unused_qualifications)]

pub mod request;
pub mod response;

#[cfg(feature="standalone")]
pub use self::chasm::query_client::QueryClient as ChasmClient;
#[cfg(feature="standalone")]
pub use cosmos::auth::v1beta1::query_client::QueryClient as AuthClient;
#[cfg(feature="standalone")]
pub use cosmos::tx::v1beta1::service_client::ServiceClient as TxClient;


#[cfg(feature="standalone")]
#[path = "proto/client/chasm.rs"]
pub mod chasm;

#[cfg(not(feature="standalone"))]
#[path = "proto/no-client/chasm.rs"]
pub mod chasm;


#[path = "./"]
pub mod cosmwasm {
    #[path = "./"]
    pub mod wasm{
        #[cfg(feature="standalone")]
        #[path = "./proto/client/cosmwasm.wasm.v1.rs"]
        pub mod v1;
        #[cfg(not(feature="standalone"))]
        #[path = "./proto/no-client/cosmwasm.wasm.v1.rs"]
        pub mod v1;
    }
}
#[path = "./"]
pub mod cosmos {
    #[path = "./"]
    pub mod auth {
        #[cfg(feature="standalone")]
        #[path = "./proto/client/cosmos.auth.v1beta1.rs"]
        pub mod v1beta1;
        #[cfg(not(feature="standalone"))]
        #[path = "./proto/no-client/cosmos.auth.v1beta1.rs"]
        pub mod v1beta1;
    }
    #[path = "./"]
    pub mod base {
        #[path = "./"]
        pub mod query {
            #[cfg(feature="standalone")]
            #[path = "./proto/client/cosmos.base.query.v1beta1.rs"]
            pub mod v1beta1;
            #[cfg(not(feature="standalone"))]
            #[path = "./proto/no-client/cosmos.base.query.v1beta1.rs"]
            pub mod v1beta1;
        }
        #[cfg(feature="standalone")]
        #[path = "./proto/client/cosmos.base.v1beta1.rs"]
        pub mod v1beta1;
        #[cfg(not(feature="standalone"))]
        #[path = "./proto/no-client/cosmos.base.v1beta1.rs"]
        pub mod v1beta1;
    }
    #[path = "./"]
    pub mod tx {
        #[cfg(feature="standalone")]
        #[path = "./proto/client/cosmos.tx.v1beta1.rs"]
        pub mod v1beta1;
        #[cfg(not(feature="standalone"))]
        #[path = "./proto/no-client/cosmos.tx.v1beta1.rs"]
        pub mod v1beta1;
    }
}
