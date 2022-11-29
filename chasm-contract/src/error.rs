use std::num::NonZeroU32;

use cosmwasm_std::StdError;
use thiserror::Error;

use chasm_types::{api::Re, crypto::Error as ChasmError};

#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("AlreadyEchoed")]
    AlreadyEchoed {echo: String},

    #[error("AlreadyRequested")]
    AlreadyRequested {re: Re},

    #[error("RequestNotFound")]
    RequestNotFound{re: Re},

    #[error("KeyExists")]
    KeyExists{name: String},

    #[error("KeyNotFound")]
    KeyNotFound{name: String},

    #[error("NotEnoughActiveParticipants")]
    NotEnoughActiveParticipants{active: Vec<NonZeroU32>, inactive: Vec<NonZeroU32>},

    #[error("InternalCryptoError {0}")]
    InternalCryptoError(ChasmError),
}
