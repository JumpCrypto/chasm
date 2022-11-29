
pub use std::collections::{BTreeMap as Map, BTreeSet as Set};

pub type Result<T> = core::result::Result<T, Error>;

pub type Participant = core::num::NonZeroU32;
pub type Threshold = core::num::NonZeroU32;

/// Participant defined by its x-coordinate.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, thiserror::Error, schemars::JsonSchema)]
pub enum Error {
    // #[error("some participant commitments are missing")]
    // MissingCommitments(Vec<Participant>),
    #[error("setup is invalid")]
    InvalidSetup,
    #[error("participant is not in participants or quorum")]
    InvalidParticipant,
    #[error("some participants sent invalid commitments")]
    InvalidCommitments(Vec<Participant>),
    #[error("something wrong with the quorum of participants chosen")]
    UnqualifiedQuorum(Set<Participant>),
    #[error("some participants sent invalid shares")]
    InvalidShares(Vec<Participant>),
    #[error("some participants sent invalid signatures")]
    InvalidSignatures(Vec<Participant>),
    // using String instead of Uuid because Uuid is not Deserialize
    #[error("not all members of quorum signed")]
    MissingQuorumSignatures,
    #[error("not all members of quorum committed in keygen")]
    MissingKeygenCommitments,
    #[error("not all members of quorum contributed in keygen")]
    MissingKeygenContributions,
    #[error("not all members of quorum committed in precompute")]
    MissingPrecomputeCommitments,
    #[error("trying to sign with unknown nonce")]
    UnknownNonce(String),
}

