//! Cryptographic backend implementations

// use ed25519_consensus::{SigningKey as Ed255SecretKey, VerificationKey as Ed255PublicKey, Signature as Ed255Signature};
use ed25519_dalek::{Keypair as Ed255SecretKey, PublicKey as Ed255PublicKey, Signature as Ed255Signature};
pub use x25519_dalek::{StaticSecret as X255SecretKey, PublicKey as X255PublicKey};
use k256::ecdsa::{SigningKey as K256SecretKey, VerifyingKey as K256PublicKey, recoverable::Signature as K256Signature};
use k256::schnorr::{SigningKey as K256TaprootSecretKey, VerifyingKey as K256TaprootPublicKey, Signature as K256TaprootSignature};
use p256::ecdsa::{SigningKey as P256SecretKey, VerifyingKey as P256PublicKey, Signature as P256Signature};
use age::x25519::{Identity as AgeX255SecretKey, Recipient as AgeX255PublicKey};
use curve25519_dalek::{
    ristretto::RistrettoPoint as Point,
    scalar::Scalar,
};

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct Ristretto255Signature {
    pub R: Point,
    pub s: Scalar,
}

impl Ristretto255Signature {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.R.compress().to_bytes());
        bytes[32..].copy_from_slice(self.s.as_bytes());
        bytes
    }
}

#[allow(unsafe_code)]
mod unsafe_casts;
pub use unsafe_casts::*;

use rand_core5::OsRng as OsRng5;
use rand_core::{CryptoRng as CryptoRng6, RngCore as RngCore6, OsRng as OsRng6};

// use ecdsa::hazmat::SignPrimitive as _;
use pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _};


// TODO: factor out this reader/writer stuff into functions
// pub(crate) fn age_decrypt(ciphertext: &[u8], key: &impl age::Identity) -> Result<Vec<u8>> {
//     let decryptor = match age::Decryptor::new(ciphertext).ok()? {
//         age::Decryptor::Recipients(d) => d,
//         _ => unreachable!(),
//     };
//
//     let mut plaintext = vec![];
//     #[allow(trivial_casts)]
//     // unclear why this warns, but removing the cast fails
//     let mut reader = decryptor.decrypt(std::iter::once(key))
//         //     // crate::crypto::sk_ref_x255_to_age(key) as &dyn age::Identity))
//             // crate::crypto::sk_ref_x255_to_age(key) as _))
//         .expect("identity key is valid");
//     use std::io::Read as _;
//     reader.read_to_end(&mut plaintext)
//         .expect("can read to end");
//
//     Ok(plaintext)
// }

#[allow(unsafe_code)]
#[derive(Copy, Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, thiserror::Error, schemars::JsonSchema)]
pub enum Operation {
    // #[error("cannot generate {0} keys")]
    // GenerateKey(Algorithm),
    // #[error("cannot generate {0} keys")]
    // UnwrapKey(Algorithm),
    // Sign(Algorithm),
    #[error("cannot deserialize {0} public keys from {1}")]
    DeserializePublicKey(Algorithm, PublicKeyFormat),
    #[error("cannot serialize {0} public keys as {1}")]
    SerializePublicKey(Algorithm, PublicKeyFormat),
    #[error("cannot deserialize {0} secret keys from {1}")]
    DeserializeSecretKey(Algorithm, SecretKeyFormat),
    #[error("cannot serialize {0} secret keys as {1}")]
    SerializeSecretKey(Algorithm, SecretKeyFormat),
    #[error("cannot serialize {0} signature as {1}")]
    SerializeSignature(Algorithm, SignatureFormat),
    #[error("{0} does not have public keys")]
    PublicKey(Algorithm),
    #[error("{0} can not derive children")]
    DeriveChild(Algorithm),
    #[error("{0} can not sign")]
    Sign(Algorithm),
    #[error("{0} can not decrypt")]
    Decrypt(Algorithm),
}

// TODO: Decide if we use errors or options.
// Motivation for options: don't reveal causes of errors outside debug builds
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, thiserror::Error, schemars::JsonSchema)]
pub enum Error {
    // TODO: THis is not really a `crypto::Error`, where to move it?
    #[error("incomplete request")]
    IncompleteRequest,
    #[error("invalid operation")]
    InvalidOperation(#[from] Operation),
    #[error("invalid data for {0} public key in {1} format")]
    InvalidPublicKey(Algorithm, PublicKeyFormat),
    #[error("invalid data for {0} secret key in {1} format")]
    InvalidSecretKey(Algorithm, SecretKeyFormat),
    #[error("invalid data for {0} decryption")]
    InvalidEncryptedData(Algorithm),
    #[error("invalid length {0} for digest")]
    InvalidDigest(usize),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("malformed signature")]
    MalformedSignature,
    #[error("malformed digest")]
    MalformedDigest,
    // todo: signal which
    #[error("invalid participants")]
    InvalidParticipants(Vec<u32>),
    #[error("invalid threshold {0}")]
    InvalidThreshold(u32),
    #[error("unknown code")]
    UnknownCode(#[from] Code),
    #[error("existing key")]
    // ExistingKey(String),
    ExistingKey,
    #[error("existing precomputation")]
    ExistingPrecomputation,
    #[error("unknown key")]
    // UnknownKey(String),
    // UnknownKey([u8; 128]),
    UnknownKey,
    #[error("unknown precomputation")]
    // UnknownKey(String),
    // UnknownKey([u8; 128]),
    UnknownPrecomputation,
    #[error("unknown algorithm name {0}")]
    UnknownAlgorithmName(String),
    #[error("unknown public key format name {0}")]
    UnknownPublicKeyFormatName(String),
    #[error("unknown signature format name {0}")]
    UnknownSignatureFormatName(String),
    #[error("existing request")]
    ExistingRequest,
    #[error("unknown request")]
    UnknownRequest,
    #[error("unknown format")]
    UnknownFormat,
    #[error("Error in FROST")]
    Frost(crate::frost::Error),
    #[error("threshold method called on single-node signer")]
    NotACluster,
    #[error("not supported")]
    NotSupported,
    #[error("threshold method called on a local key")]
    NotAThresholdKey,
    // #[error("threshold method called with less participants than the threshold")]
    // NotEnoughParticipants(u32),
    // #[error("threshold method called with participants not containing this node")]
    // NotInParticipants(u32),
    // #[error("threshold method called with unexpected participants")]
    // UnexpectedParticipants,
    #[error("so far unspecific error in a threshold protocol")]
    Malfeasance,
    #[error("a very rare case occurred: key + tweak is zero or overflows")]
    UnluckyChild,
    #[error("we may or may not in the future allow skipping the precompute step and doing it inline")]
    DynamicPrecomputeNotImplemented,
    #[error("some network communication round timed out")]
    TimedOut(Vec<u32>),
    #[error("thresholding not implemented for algorithm")]
    ThresholdingNotImplemented(Algorithm),
    #[error("wrong signature share sent")]
    WrongSignatureShare,
    #[error("network disconnect while collecting in threshold process")]
    NetworkDisconnectWhileCollecting,
    #[error("duplicate message sent in threshold process")]
    DuplicateMessage,
    #[error("Failed request")]
    FailedRequest(String),
}

#[cfg(feature="standalone")]
impl From<Error> for jsonrpsee::core::Error {
    fn from(e: Error) -> Self {
        jsonrpsee::core::Error::Custom(e.to_string())
    }
}

impl From<crate::frost::Error> for Error {
    fn from(e: crate::frost::Error) -> Self {
        Self::Frost(e)
    }
}

#[derive(Copy, Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, thiserror::Error, schemars::JsonSchema)]
pub enum Code {
    #[error("unknown algorithm code {0}")]
    Algorithm(i32),
    #[error("unknown public key format code {0}")]
    PublicKeyFormat(i32),
    #[error("unknown secret key format code {0}")]
    SecretKeyFormat(i32),
    #[error("unknown signature key format code {0}")]
    SignatureFormat(i32),
}

pub type Result<T> = std::result::Result<T, Error>;

enumerated_enum!(
/// Algorithms supported in this chasm implementation
///
/// Note that the top bit is used to distinguish threshold (bit set)
/// from non-threshold (bit not set) keys.
Algorithm:

    /// Not really an algorithm: 32 bytes of entropy
    #[default]
    Secret = 0,
    Ed255 = 1,
    K256 = 2,
    P256 = 3,
    X255 = 4,

    Ristretto255 = 5,
    K256Taproot = 6,
);

impl core::str::FromStr for Algorithm {
    type Err = Error;
    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            // "secret" => Self::Secret,
            "ed255" => Self::Ed255,
            "p256" => Self::P256,
            "k256" => Self::K256,
            "x255" => Self::X255,
            "ristretto255" => Self::Ristretto255,
            "k256-taproot" => Self::K256Taproot,
            _ => return Err(Error::UnknownAlgorithmName(s.into())),
        })
    }
}

enumerated_enum!(
/// Formats public keys can be serialized.
PublicKeyFormat:
    #[default]
    Unknown = 0,
    /// Raw encoding (64 bytes with x/y coordinate)
    Raw = 1,
    /// SEC1 compressed encoding (`0x02` or `0x03`, then the x-coordinate)
    CompressedPoint = 2,
    /// SEC1 uncompressed encoding (`0x04`, then the same as raw)
    UncompressedPoint = 3,
    /// `age`'s recipient format (ASCII-encoded as bytes). Example:
    /// `age1qamzpkm4tzlasz3dm6550gvkggh58uwp2taqzmjwehmutyjzu55skss26v`
    Age = 4,
);

impl core::str::FromStr for PublicKeyFormat {
    type Err = Error;
    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "raw" => Self::Raw,
            "compressed" => Self::CompressedPoint,
            "uncompressed" => Self::UncompressedPoint,
            "age" => Self::Age,
            _ => return Err(Error::UnknownPublicKeyFormatName(s.to_string())),
        })
    }
}

enumerated_enum!(
/// Formats secret keys can be serialized.
SecretKeyFormat:
    #[default]
    Unknown = 0,
    /// Raw encoding (the secret scalar as 32 byte big-endian integer)
    Raw = 1,
    /// PrivateKeyInfo as in PKCS #8
    Pki = 2,
    /// Encoding of the 32 bytes of entropy/secrets as 24 English words (cf. BIP 39).
    /// Note that not all 24 words are valid encodings as there is a checksum included.
    ///
    /// Also note that there is no KDF involved as in BIP 32, this is a reversible
    /// encoding of the raw secret.
    Phrase = 3,
    /// `age`'s identity format (ASCII-encoded as bytes). Example:
    /// `AGE-SECRET-KEY-1HR479D3GGXAF0F9QGZU4KMZZXC7SHSURR5QWHC8ZN264RUKMPFGSMTH26K`
    Age = 4,
);

impl core::str::FromStr for SecretKeyFormat {
    type Err = Error;
    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "raw" => Self::Raw,
            "pki" => Self::Pki,
            "phrase" => Self::Phrase,
            "age" => Self::Age,
            _ => return Err(Error::UnknownAlgorithmName(s.into())),
        })
    }
}

enumerated_enum!(
/// Formats signatures can be serialized.
SignatureFormat:

    #[default]
    Unknown= 0,
    /// Raw encoding of the (r, s) pair as two consecutive 32 byte big-endian integers
    Raw = 1,
    /// Raw encoding with recovery byte (65 bytes)
    RawWithRecovery = 2,
    /// DER encoding of the (r, s) pair: SEQUENCE 0x30, length, INTEGER 0x02, length, <r as ASN.1
    /// integer>, INTEGER 0x02, length, <s as ASN.1 integer>. Typical length ~70 bytes.
    Der = 3,
);

impl core::str::FromStr for SignatureFormat {
    type Err = Error;
    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "raw" => Self::Raw,
            "raw-with-recovery" => Self::RawWithRecovery,
            "der" => Self::Der,
            _ => return Err(Error::UnknownSignatureFormatName(s.to_string())),
        })
    }
}

/// Default public key format.
impl TryFrom<Algorithm> for PublicKeyFormat {
    type Error = Error;
    fn try_from(algorithm: Algorithm) -> Result<PublicKeyFormat> {
        use Algorithm::*;
        use PublicKeyFormat::*;
        Ok(match algorithm {
            Secret => return Err(Error::InvalidOperation(Operation::PublicKey(Secret))),
            K256Taproot | Ed255 | X255 | Ristretto255 => Raw,
            K256 | P256 => CompressedPoint,
        })
    }
}

/// Default secret key format.
impl From<Algorithm> for SecretKeyFormat {
    fn from(_algorithm: Algorithm) -> SecretKeyFormat {
        //use Algorithm::*;
        //use SecretKeyFormat::*;
        //
        // !!! NOTE !!!
        //
        // Older versions stored age/x255 keys in age format.
        // These will no longer unmarshal.
        //
        // match algorithm {
        //     X255 => Age,
        //     _ => Raw,
        // }
        SecretKeyFormat::Raw
    }
}

/// Default signature format.
impl TryFrom<Algorithm> for SignatureFormat {
    type Error = Error;
    fn try_from(algorithm: Algorithm) -> Result<SignatureFormat> {
        use Algorithm::*;
        use SignatureFormat::*;
        Ok(match algorithm {
            K256Taproot | Ed255 | Ristretto255 => Raw,
            K256 => Der,
            P256 => Der,
            _ => return Err(Error::InvalidOperation(Operation::Sign(algorithm))),
        })
    }
}

// age::x25519::Identity is not Debug :/
// #[derive(/*Clone,*/ Debug)]
pub enum SecretKey {
    Secret(Secret),
    Ed255(Ed255SecretKey),
    K256(K256SecretKey),
    K256Taproot(K256TaprootSecretKey),
    P256(P256SecretKey),
    X255(X255SecretKey),
}

// age::x25519::Recipient is not Copy nor Debug :/
// #[derive(Clone, Copy, Debug)]
#[derive(Clone)]
pub enum PublicKey {
    Ed255(Ed255PublicKey),
    K256(K256PublicKey),
    K256Taproot(K256TaprootPublicKey),
    P256(P256PublicKey),
    X255(X255PublicKey),
}

#[derive(Clone)]
pub enum Signature {
    Ed255(Ed255Signature),
    K256(K256Signature),
    K256Taproot(K256TaprootSignature),
    P256(P256Signature),
    Ristretto255(Ristretto255Signature),
}

impl PublicKey {

    pub fn from_raw(algorithm: Algorithm, bytes: &[u8]) -> Result<Self> {
        let err = Error::InvalidPublicKey(algorithm, PublicKeyFormat::Raw);
        Ok(match algorithm {
            Algorithm::Ed255 => PublicKey::Ed255(Ed255PublicKey::from_bytes(bytes).map_err(|_| err)?),
            Algorithm::K256Taproot => PublicKey::K256Taproot(K256TaprootPublicKey::from_bytes(bytes).map_err(|_| err)?),
            Algorithm::K256 => PublicKey::K256(K256PublicKey::from_sec1_bytes(bytes).map_err(|_| err)?),
            Algorithm::P256 => PublicKey::P256(bytes.try_into().map_err(|_| err)?),
            Algorithm::X255 => {
                let fixed_bytes: [u8; 32] = bytes.try_into().map_err(|_| err)?;
                PublicKey::X255(fixed_bytes.into())
            }
            _ => return Err(Error::InvalidOperation(Operation::PublicKey(algorithm))),
        })
    }


    pub fn algorithm(&self) -> Algorithm {
        use PublicKey::*;
        match self {
            Ed255(_) => Algorithm::Ed255,
            K256(_) => Algorithm::K256,
            K256Taproot(_) => Algorithm::K256Taproot,
            P256(_) => Algorithm::P256,
            X255(_) => Algorithm::X255,
        }
    }

    // for storage: serialize with default format
    pub fn marshal(&self) -> Vec<u8> {
        // NB: Only algorithms with a default public key format are in the PublicKey enum
        // NB: Default key formats are serializable
        self.serialize(self.algorithm().try_into().unwrap()).unwrap()
    }

    pub fn serialize(&self, format: PublicKeyFormat) -> Result<Vec<u8>> {
        use PublicKeyFormat::*;
        match format {
            Unknown => Err(Error::UnknownFormat),
            Raw => self.raw(),
            CompressedPoint => self.compressed_point(),
            UncompressedPoint => self.uncompressed_point(),
            Age => self.age(),
        }
    }

    pub fn raw(&self) -> Result<Vec<u8>> {
        use PublicKey::*;
        match self {
            K256Taproot(key) => Ok(key.to_bytes().to_vec()),
            Ed255(key) => Ok(key.to_bytes().to_vec()),
            X255(key) => Ok(key.to_bytes().to_vec()),
            K256(_) | P256(_) => Ok(self.compressed_point()?[1..].to_vec()),
            // _ => Err(Error::InvalidOperation(Operation::SerializePublicKey(self.algorithm(), PublicKeyFormat::Raw)))
        }
    }

    // sec1 (compressed), aka CompressedPoint
    pub fn compressed_point(&self) -> Result<Vec<u8>> {
        use PublicKey::*;
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        Ok(match self {
            K256(key) => key.to_encoded_point(true).as_bytes().to_vec(),
            P256(key) => key.to_encoded_point(true).as_bytes().to_vec(),
            _ => return Err(Error::InvalidOperation(Operation::SerializePublicKey(self.algorithm(), PublicKeyFormat::CompressedPoint))),
        })
    }

    // sec1 (uncompressed), aka UncompressedPoint
    pub fn uncompressed_point(&self) -> Result<Vec<u8>> {
        use PublicKey::*;
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        Ok(match self {
            K256(key) => key.to_encoded_point(false).as_bytes().to_vec(),
            P256(key) => key.to_encoded_point(false).as_bytes().to_vec(),
            _ => return Err(Error::InvalidOperation(Operation::SerializePublicKey(self.algorithm(), PublicKeyFormat::UncompressedPoint))),
        })
    }

    pub fn age(&self) -> Result<Vec<u8>> {
        use PublicKey::*;
        match self {
            X255(key) => Ok(format!("{}", &pk_x255_to_age(*key)).as_bytes().to_vec()),
            _ => Err(Error::InvalidOperation(Operation::SerializePublicKey(self.algorithm(), PublicKeyFormat::Age)))
        }
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        use PublicKey::*;
        use sha2::Digest;
        match self {
            K256Taproot(key) => {
                let digest = Update::chain(sha2::Sha256::default(), message);
                let raw_digest = digest.finalize();
                let signature = K256TaprootSignature::from_bytes(signature).map_err(|_| Error::MalformedSignature)?;
                key.verify_raw_digest(raw_digest.as_slice().try_into().map_err(|_| Error::MalformedDigest)?, &signature).map_err(|_| Error::InvalidSignature)
            },
            Ed255(key) => {
                let signature = Ed255Signature::from_bytes(signature).map_err(|_| Error::MalformedSignature)?;
                key.verify_strict(message, &signature).map_err(|_| Error::InvalidSignature)
            },
            K256(key) => {
                use ecdsa::signature::{DigestVerifier, Signature};
                let digest = Update::chain(sha2::Sha256::default(), message);
                let signature = K256Signature::from_bytes(signature).map_err(|_| Error::MalformedSignature)?;

                key.verify_digest(digest, &signature).map_err(|_| Error::InvalidSignature)
            }
            P256(key) => {
                use ecdsa::signature::{DigestVerifier, Signature};
                let digest = Update::chain(sha2::Sha256::default(), message);
                let signature = P256Signature::from_bytes(signature).map_err(|_| Error::MalformedSignature)?;

                key.verify_digest(digest, &signature).map_err(|_| Error::InvalidSignature)
            }
            _ => Err(Error::InvalidSignature),
            // _ => Err(Error::InvalidOperation(Operation::SerializePublicKey(self.algorithm(), PublicKeyFormat::Raw)))
        }
    }

    pub fn verify_digest(&self, digest: &[u8], signature: &[u8]) -> Result<()> {
        use PublicKey::*;
        // use sha2::Digest;
        use ecdsa::signature::{DigestVerifier, Signature};
        match self {
            K256Taproot(key) => {
                let signature = K256TaprootSignature::from_bytes(signature).map_err(|_| Error::MalformedSignature)?;
                key.verify_raw_digest(digest.try_into().map_err(|_| Error::MalformedDigest)?, &signature).map_err(|_| Error::InvalidSignature)
            },
            Ed255(_key) => {
                Err(Error::NotSupported)
            },
            K256(key) => {
                let digest = Fake256::from(&digest.try_into().map_err(|_| Error::MalformedDigest)?);
                let signature = K256Signature::from_bytes(signature).map_err(|_| Error::MalformedSignature)?;

                key.verify_digest(digest, &signature).map_err(|_| Error::InvalidSignature)
            }
            P256(key) => {
                let digest = Fake256::from(&digest.try_into().map_err(|_| Error::MalformedDigest)?);
                let signature = P256Signature::from_bytes(signature).map_err(|_| Error::MalformedSignature)?;

                key.verify_digest(digest, &signature).map_err(|_| Error::InvalidSignature)
            }
            _ => Err(Error::InvalidSignature),
            // _ => Err(Error::InvalidOperation(Operation::SerializePublicKey(self.algorithm(), PublicKeyFormat::Raw)))
        }
    }

}

impl SecretKey {
    pub fn algorithm(&self) -> Algorithm {
        use SecretKey::*;
        match self {
            Secret(_) => Algorithm::Secret,
            Ed255(_) => Algorithm::Ed255,
            K256(_) => Algorithm::K256,
            K256Taproot(_) => Algorithm::K256Taproot,
            P256(_) => Algorithm::P256,
            X255(_) => Algorithm::X255,
        }
    }

    pub fn public(&self) -> Result<PublicKey> {
        use PublicKey::*;
        Ok(match self {
            SecretKey::Ed255(key) => Ed255(key.public),
            SecretKey::K256(key) => K256(key.verifying_key()),
            SecretKey::K256Taproot(key) => K256Taproot(key.verifying_key()),
            SecretKey::P256(key) => P256(key.verifying_key()),
            SecretKey::X255(key) => X255(key.into()),
            _ => return Err(Error::InvalidOperation(Operation::PublicKey(self.algorithm()))),
        })
    }

    /// Serialize the key into its default format, prepending the serialized algorithm byte
    pub fn marshal(&self) -> Vec<u8> {
        let mut bytes = vec![self.algorithm() as u8];
        let key_bytes = self.serialize(self.algorithm().into()).unwrap();
        bytes.extend_from_slice(&key_bytes);
        bytes
    }

    /// Serialize a key in a given format (no algorithm byte)
    pub fn serialize(&self, format: SecretKeyFormat) -> Result<Vec<u8>> {
        use SecretKeyFormat::*;
        match format {
            Unknown => Err(Error::UnknownFormat),
            Raw => self.raw(),
            Pki => self.pki(),
            Phrase => self.phrase(),
            Age => self.age(),
        }
    }

    /// Deserialize a key, using the first byte to determine its algorithm
    pub fn unmarshal(bytes: &[u8]) -> Result<Self> {
        let algorithm = Algorithm::try_from(bytes[0])?;
        let key_bytes = &bytes[1..];
        Self::deserialize(algorithm, key_bytes, algorithm.into())
    }

    /// Deserialize a given algorithm's key from a given format
    pub fn deserialize(algorithm: Algorithm, bytes: &[u8], format: SecretKeyFormat) -> Result<Self> {
        use SecretKeyFormat::*;
        match format {
            Unknown => Err(Error::UnknownFormat),
            Raw => Self::from_raw(algorithm, bytes),
            Pki => Self::from_pki(algorithm, bytes),
            Phrase => Self::from_phrase(algorithm, bytes),
            Age => Self::from_age(algorithm, bytes),
        }
    }

    pub fn raw(&self) -> Result<Vec<u8>> {
        use SecretKey::*;
        Ok(match self {
            Secret(secret) => secret.0.to_vec(),
            Ed255(key) => key.to_bytes().to_vec(),
            K256(key) => key.to_bytes().to_vec(),
            K256Taproot(key) => key.to_bytes().to_vec(),
            P256(key) => key.to_bytes().to_vec(),
            X255(key) => key.to_bytes().to_vec(),
            // _ => return Err(Error::InvalidOperation(Operation::SerializeSecretKey(self.algorithm(), SecretKeyFormat::Raw))),
        })
    }

    pub fn from_raw(algorithm: Algorithm, bytes: &[u8]) -> Result<Self> {
        Ok(match algorithm {
            Algorithm::Secret => SecretKey::Secret(Secret(bytes.try_into()
                .map_err(|_| Error::InvalidSecretKey(algorithm, SecretKeyFormat::Raw))?)),
            Algorithm::Ed255 =>SecretKey::Ed255(Ed255SecretKey::from_bytes(bytes)
                .map_err(|e| {
                    println!("Ed secret key error: {}", e);
                    Error::InvalidSecretKey(algorithm, SecretKeyFormat::Raw)
                })?),
            Algorithm::P256 => SecretKey::P256(P256SecretKey::from_bytes(bytes)
                .map_err(|_| Error::InvalidSecretKey(algorithm, SecretKeyFormat::Raw))?),
            Algorithm::K256 => SecretKey::K256(K256SecretKey::from_bytes(bytes)
                .map_err(|_| Error::InvalidSecretKey(algorithm, SecretKeyFormat::Raw))?),
            Algorithm::K256Taproot => SecretKey::K256Taproot(K256TaprootSecretKey::from_bytes(bytes)
                .map_err(|_| Error::InvalidSecretKey(algorithm, SecretKeyFormat::Raw))?),
            Algorithm::X255 => {
                let bytes: [u8; 32] = bytes.try_into()
                    .map_err(|_| {
                        println!("Invalid length X255 key: {}", bytes.len());
                        Error::InvalidSecretKey(algorithm, SecretKeyFormat::Raw)
                    })?;
                SecretKey::X255(X255SecretKey::from(bytes))
            }
            Algorithm::Ristretto255 =>
                return Err(Error::InvalidOperation(Operation::DeserializeSecretKey(algorithm, SecretKeyFormat::Raw))),
            // _ => return Err(Error::InvalidOperation(Operation::DeserializeSecretKey(algorithm, SecretKeyFormat::Raw))),
        })
    }

    pub fn pki(&self) -> Result<Vec<u8>> {
        use SecretKey::*;
        Ok(match self {
            // Ed255(key) => ? (it's defined)
            K256(key) => {
                let secret_key: k256::SecretKey = key.into();
                secret_key.to_pkcs8_der().unwrap().as_ref().to_vec()
            }
            // TODO: some weird bug/limitation in `p256`.
            // P256(key) => {
            //     let secret_key: p256::SecretKey = key.into();
            //     secret_key.to_pkcs8_der().unwrap().as_ref().to_vec()
            // }
            _ => return Err(Error::InvalidOperation(Operation::SerializeSecretKey(self.algorithm(), SecretKeyFormat::Pki))),
        })
    }

    pub fn from_pki(algorithm: Algorithm, bytes: &[u8]) -> Result<Self> {
        Ok(match algorithm {
            Algorithm::K256 => {
                let secret_key = k256::SecretKey::from_pkcs8_der(bytes)
                    .map_err(|_| Error::InvalidSecretKey(algorithm, SecretKeyFormat::Pki))?;
                SecretKey::K256(secret_key.into())
            }
            Algorithm::P256 => {
                let secret_key = p256::SecretKey::from_pkcs8_der(bytes)
                    .map_err(|_| Error::InvalidSecretKey(algorithm, SecretKeyFormat::Pki))?;
                SecretKey::P256(secret_key.into())
            }
            _ => return Err(Error::InvalidOperation(Operation::DeserializeSecretKey(algorithm, SecretKeyFormat::Pki))),
        })
    }

    pub fn phrase(&self) -> Result<Vec<u8>> {
        // TODO: Handle keys that would not be 32 bytes in raw format.
        let raw: [u8; 32] = self.raw()?.try_into().unwrap();
        let phrase = bip32::Mnemonic::from_entropy(raw, bip32::Language::English);
        Ok(phrase.phrase().as_bytes().to_vec())
    }

    pub fn from_phrase(algorithm: Algorithm, bytes: &[u8]) -> Result<Self> {
        let mnemonic = std::str::from_utf8(bytes)
            .map_err(|_| Error::InvalidSecretKey(algorithm, SecretKeyFormat::Phrase))?
            .trim();
        let phrase = bip32::Mnemonic::new(mnemonic, bip32::Language::English)
            .map_err(|_| Error::InvalidSecretKey(algorithm, SecretKeyFormat::Phrase))?;
        Self::from_raw(algorithm, phrase.entropy())
    }

    pub fn age(&self) -> Result<Vec<u8>> {
        if let SecretKey::X255(key) = self {
            use secrecy::ExposeSecret;
            Ok(sk_ref_x255_to_age(key).to_string().expose_secret().as_bytes().to_vec())
        } else {
            Err(Error::InvalidOperation(Operation::SerializeSecretKey(self.algorithm(), SecretKeyFormat::Age)))
        }
    }

    pub fn from_age(algorithm: Algorithm, _bytes: &[u8]) -> Result<Self> {
        // do we actually need this? if so, resurrect it
        // if Algorithm::X255 == algorithm {
        //     let x255_key = std::str::from_utf8(bytes)
        //         .map_err(|_| Error::InvalidSecretKey(algorithm, SecretKeyFormat::Age))?
        //         .trim()
        //         .parse()
        //         .map(|age| sk_age_to_x255(age))
        //         .map_err(|_| Error::InvalidSecretKey(algorithm, SecretKeyFormat::Age))?;
        //
        //     Ok(SecretKey::X255(x255_key))
        // } else {
            Err(Error::InvalidOperation(Operation::DeserializeSecretKey(algorithm, SecretKeyFormat::Age)))
        // }
    }

    #[allow(trivial_casts)]
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if let SecretKey::X255(key) = self {
            let decryptor = match age::Decryptor::new(data)
                .map_err(|e| {
                    println!("age error initializing: {:?}", &e);
                    Error::InvalidEncryptedData(Algorithm::X255)
                })?
            {
                age::Decryptor::Recipients(d) => d,
                _ => return Err(Error::InvalidEncryptedData(Algorithm::X255)),
            };

            let mut decrypted = vec![];
            let mut reader = decryptor.decrypt(std::iter::once(sk_ref_x255_to_age(key) as &dyn age::Identity))
                .map_err(|e| {
                    println!("age error decrypting: {:?}", &e);
                    Error::InvalidEncryptedData(Algorithm::X255)
                })?;
            use std::io::Read as _;
            reader.read_to_end(&mut decrypted)
                .map_err(|e| {
                    println!("age error reading: {:?}", &e);
                    Error::InvalidEncryptedData(Algorithm::X255)
                })?;

            Ok(decrypted)
        } else {
            Err(Error::InvalidOperation(Operation::Decrypt(self.algorithm())))
        }
    }

    pub fn derive_child(&self, child: u32, chain_code: Option<&[u8; 32]>) -> Result<Self> {
        if let SecretKey::K256(key) = self {
            // re-implement the crucial part of bip32/extended_key/private_key.rs

            // use bip32::PrivateKey;
            use hmac::{Hmac, Mac as _, NewMac as _};
            type HmacSha512 = Hmac<sha2::Sha512>;

            let chain_code: [u8; 32] = chain_code.copied().unwrap_or([0; 32]);

            let mut hmac = HmacSha512::new_from_slice(&chain_code).expect("we need 32 bytes");

            // hmac.update(&key.public_key().to_bytes());
            hmac.update(&key.verifying_key().to_bytes());
            hmac.update(&child.to_be_bytes());

            let result = hmac.finalize().into_bytes();
            // let (tweak_bytes, chain_code) = result.split_at(32);
            let tweak: [u8; 32] = result[..32].try_into().expect("32 = 32");

            // performs the addition: child.scalar = key.scalar + tweak.as_scalar
            // let child_key = key.derive_child(tweak)
            //     // what can happen here is that the sum is a) zero or b) overflows the group order
            //     // according to BIP, should "loop"
            //     .map_err(|_| Error::UnluckyChild)?;

            let child_scalar =
                Option::<k256::NonZeroScalar>::from(k256::NonZeroScalar::from_repr(tweak.into()))
                    .ok_or(Error::UnluckyChild)?;

            // this should be exposed as a method instead of forcing serde...
            let key_as_scalar = k256::NonZeroScalar::from_repr(key.to_bytes()).unwrap();
            // let derived_scalar = key.to_nonzero_scalar().as_ref() + child_scalar.as_ref();
            let derived_scalar = key_as_scalar.as_ref() + child_scalar.as_ref();

            let child_key = Option::<k256::NonZeroScalar>::from(k256::NonZeroScalar::new(derived_scalar))
                .map(Into::into)
                .ok_or(Error::UnluckyChild)?;

            Ok(SecretKey::K256(child_key))

        } else {
            Err(Error::InvalidOperation(Operation::DeriveChild(self.algorithm())))
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Signature> {
        use SecretKey::*;
        Ok(match self {
            Ed255(key) => {
                use ed25519_dalek::Signer;
                Signature::Ed255(key.sign(msg))
            }

            K256(key) => Signature::K256(k256_sign_message(key, msg)),

            K256Taproot(key) => Signature::K256Taproot(k256_taproot_sign_message(key, msg)),

            P256(key) => {
                use p256::ecdsa::signature::Signer;
                Signature::P256(key.sign(msg))
            }

            _ => return Err(Error::InvalidOperation(Operation::Sign(self.algorithm()))),

        })
    }

    pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<Signature> {
        use SecretKey::*;
        Ok(match self {
            K256(key) => Signature::K256(k256_sign_digest(key, digest)),

            K256Taproot(key) => Signature::K256Taproot(k256_taproot_sign_digest(key, digest)),

            _ => return Err(Error::InvalidOperation(Operation::Sign(self.algorithm()))),
        })
    }

    pub fn new(algorithm: Algorithm) -> Self {
        match algorithm {
            Algorithm::Secret => SecretKey::Secret(Secret::random(&mut OsRng6)),
            Algorithm::Ed255 => SecretKey::Ed255(Ed255SecretKey::generate(&mut OsRng5)),
            Algorithm::K256 => SecretKey::K256(K256SecretKey::random(&mut OsRng6)),
            Algorithm::K256Taproot => SecretKey::K256Taproot(K256TaprootSecretKey::random(&mut OsRng6)),
            Algorithm::P256 => SecretKey::P256(P256SecretKey::random(&mut OsRng6)),
            Algorithm::X255 => SecretKey::X255(X255SecretKey::new(&mut OsRng5)),
            Algorithm::Ristretto255 => unimplemented!(),
        }
    }

    pub fn new_secret() -> Self { Self::new(Algorithm::Secret) }
    pub fn new_ed255() -> Self { Self::new(Algorithm::Ed255) }
    pub fn new_k256() -> Self { Self::new(Algorithm::K256) }
    pub fn new_k256_taproot() -> Self { Self::new(Algorithm::K256Taproot) }
    pub fn new_p256() -> Self { Self::new(Algorithm::P256) }
    pub fn new_x255() -> Self { Self::new(Algorithm::X255) }
}


impl Signature {
    pub fn algorithm(&self) -> Algorithm {
        use Signature::*;
        match self {
            Ed255(_) => Algorithm::Ed255,
            K256(_) => Algorithm::K256,
            K256Taproot(_) => Algorithm::K256Taproot,
            P256(_) => Algorithm::P256,
            Ristretto255(_) => Algorithm::Ristretto255,
        }
    }

    pub fn serialize(&self, format: SignatureFormat) -> Result<Vec<u8>> {
        use SignatureFormat::*;
        match format {
            Unknown => Err(Error::UnknownFormat),
            Raw => Ok(self.raw()),
            RawWithRecovery => self.raw_with_recovery(),
            Der => self.der(),
        }
    }

    pub fn raw(&self) -> Vec<u8> {
        use Signature::*;
        match self {
            Ed255(signature) => signature.to_bytes().to_vec(),
            K256(signature) => k256::ecdsa::Signature::from(*signature).as_ref().to_vec(),
            K256Taproot(signature) => signature.as_bytes().to_vec(),
            P256(signature) => signature.as_ref().to_vec(),
            Ristretto255(signature) => signature.to_bytes().to_vec(),
        }
    }

    pub fn raw_with_recovery(&self) -> Result<Vec<u8>> {
        use Signature::*;
        match self {
            K256(signature) => Ok(signature.as_ref().to_vec()),
            _ => Err(Error::InvalidOperation(Operation::SerializeSignature(self.algorithm(), SignatureFormat::RawWithRecovery)))
        }
    }

    pub fn der(&self) -> Result<Vec<u8>> {
        use Signature::*;
        Ok(match self {
            K256(signature) => k256::ecdsa::Signature::from(*signature).to_der().as_bytes().to_vec(),
            P256(signature) => signature.to_der().as_bytes().to_vec(),
            _ => return Err(Error::InvalidOperation(Operation::SerializeSignature(self.algorithm(), SignatureFormat::Der))),
        })
    }
}

#[derive(Clone)]
pub struct Secret([u8; 32]);

impl Secret {
    pub fn random(rng: impl CryptoRng6 + RngCore6) -> Self {
        let mut secret = [0u8; 32];
        let mut rng = rng;
        rng.fill_bytes(&mut secret);
        Self(secret)
    }
}

fn k256_sign_message(key: &K256SecretKey, message: &[u8]) -> K256Signature {
    // The default digest that gets chosen for `Signer` with output `recoverable::Signature` is keccak256!
    // (because Ethererum).
    // So we have to override this choice
    use ecdsa::signature::DigestSigner;
    let digest = Update::chain(sha2::Sha256::default(), message);

    key.sign_digest(digest)
}

fn k256_sign_digest(key: &K256SecretKey, digest: &[u8; 32]) -> K256Signature {
    use ecdsa::signature::DigestSigner;
    let msg_digest = Fake256::from(digest);
    key.sign_digest(msg_digest)
}

fn k256_taproot_sign_message(key: &K256TaprootSecretKey, message: &[u8]) -> K256TaprootSignature {
    use sha2::Digest;
    let digest = Update::chain(sha2::Sha256::default(), message);
    let raw_digest = digest.finalize();

    k256_taproot_sign_digest(key, raw_digest.as_ref())
}

fn k256_taproot_sign_digest(key: &K256TaprootSecretKey, digest: &[u8; 32]) -> K256TaprootSignature {
    // TODO: do we want non-deterministic signatures or not?
    let aux_rand = [0u8; 32];
    key
        .try_sign_raw_digest(digest, &aux_rand)
        .expect("no super-rare signing errors")
}


/// Pretty dirty hack.
///
/// For security reasons, `signature::DigestSigner` doesn't want you to sign raw bytes.
/// However, we have a trusted client, and want it to be able to send the raw bytes for efficiency,
/// also because the blockchain messages internally calculate and independently use the hash.
///
/// So... we need to have a structure that
/// a) acts like a real Sha256 if initiated with Default and then updated + finalized
/// b) returns our desired pre-existing hash as final output if initiated from that
#[derive(Clone, Debug)]
enum Fake256 {
    Real(sha2::Sha256),
    Fake([u8; 32]),
}

impl Default for Fake256 {
    fn default() -> Self {
        Self::Real(sha2::Sha256::default())
    }
}

impl From<&[u8; 32]> for Fake256 {
    fn from(raw_digest: &[u8; 32]) -> Self {
        Self::Fake(*raw_digest)
    }
}

use generic_array::GenericArray;
use k256::ecdsa::signature::digest::{BlockInput, FixedOutput, Reset, Update};
impl BlockInput for Fake256 {
    type BlockSize = <sha2::Sha256 as BlockInput>::BlockSize;
}

impl FixedOutput for Fake256 {
    type OutputSize = <sha2::Sha256 as FixedOutput>::OutputSize;

    fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
        // println!("finalize_into");
        match self {
            Self::Real(sha2) => sha2.finalize_into(out),
            Self::Fake(digest) => out.as_mut_slice().copy_from_slice(&digest),
        }
    }

    fn finalize_into_reset(&mut self, out: &mut GenericArray<u8, Self::OutputSize>) {
        // println!("finalize_into_reset");
        match self {
            Self::Real(sha2) => sha2.finalize_into_reset(out),
            Self::Fake(digest) => out.as_mut_slice().copy_from_slice(digest),
        }
        // self.reset();
    }

}

impl Update for Fake256 {
    fn update(&mut self, data: impl AsRef<[u8]>) {
        // println!("update");
        match self {
            Self::Real(sha2) => sha2.update(data),
            Self::Fake(_) => panic!("this case should not occur"),
        }
    }
}

impl Reset for Fake256 {
    fn reset(&mut self) {
        // println!("reset");
        *self = Self::default();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn fake256() {
        let hash = <[u8; 32]>::try_from(hex::decode("04e3d3f18309a89c283a9d1fd8a3eba7db4be6da9f156ab67c4830cd06270244").unwrap().as_slice()).unwrap();
        let digest = Fake256::from(&hash);
        let out = digest.finalize_fixed();
        assert_eq!(hash, out.as_slice());
    }

    #[test]
    fn derive_k256_child() {
        // Nikhil's example
        let parent_key = SecretKey::from_raw(
            Algorithm::K256,
            // &hex::decode("04e3d3f18309a89c283a9d1fd8a3eba7db4be6da9f156ab67c4830cd06270244").unwrap(),
            &hex::decode("b13e7b772905aa0d3fcda96dfcea86ae0ca532fe269cf312f9da489691b66e3f").unwrap(),
        ).unwrap();

        let child_key = parent_key.derive_child(0, None)
            .expect("can derive child 0");

        let expected_child_public = hex::decode(
            "023c4b5bdc7be8bde65307558966727ba3c019089d4877cac5398189e5d9d91971").unwrap();
        let child_public = child_key.public()
            .expect("have public")
            .compressed_point()
            .expect("can encode raw");
        assert_eq!(expected_child_public, child_public);

    }

    #[test]
    fn k256_sign_digest() {
        let secret_key = SecretKey::from_raw(
            Algorithm::K256,
            &hex::decode("04e3d3f18309a89c283a9d1fd8a3eba7db4be6da9f156ab67c4830cd06270244").unwrap(),
        ).unwrap();

        let sighash: [u8; 32] = hex::decode("9aaf18ad186ee014bd7e5a9b734a4edd3dd62136b504bee2009c0a183b093ab0").unwrap().try_into().unwrap();

        // if let SecretKey::K256(key) = &secret_key {
        //     // let sig_a = super::k256_sign_digest(key, &sighash);
        //     // let sig_b = k256_sign_digest_wrong(key, &sighash);
        //     use k256::ecdsa::signature::Signer;
        //     let sig_a: k256::ecdsa::Signature = key.sign(&sighash);
        //     let sig_b: k256::ecdsa::recoverable::Signature = key.sign(&sighash);
        //     let sig_c: k256::ecdsa::Signature = sig_b.into();

        //     // assert_eq!(hex::encode(sig_b), hex::encode(sig_c));
        //     assert_eq!(hex::encode(sig_a), hex::encode(sig_c));
        //     assert_eq!(hex::encode(sig_a), hex::encode(sig_b));
        // }

        let signature_hashing = secret_key.sign(&sighash).unwrap();
        let signature_prehashed = secret_key.sign_digest(&sighash).unwrap();

        // only diff is additional recovery byte
        assert_eq!(
            hex::encode(signature_prehashed.raw()),
            hex::encode(signature_prehashed.raw_with_recovery().unwrap())[..128],
        );

        // // our prehashed version uses the same r
        // assert_eq!(
        //     hex::encode(signature_hashing.raw())[..64],
        //     hex::encode(signature_prehashed.raw())[..64],
        // );

        // the signature s is different though
        assert_ne!(
            hex::encode(signature_hashing.raw())[64..],
            hex::encode(signature_prehashed.raw())[64..],
        );
        // assert_eq!(
        //     hex::encode(signature_hashing.raw())[64..],
        //     hex::encode(signature_prehashed.raw())[64..],
        // );

        // OUTDATED COMMENT:
        // This fails - I'm not sure if it should be possible.
        //
        // Due to the way `k256` is setup, we can't implement sign_digest in a way such that
        // sign_digest(digest(msg)) = sign(msg), where msg := sighash
        //
        // The difference is in which ephemeral point is chosen.
        //
        // However, it still needs to be the case that `sign_digest(digest(msg))`
        // verifies as a valid signature for `msg`.
        //
        // CURRENT COMMENT:
        // This now works: `sign_digest ∘ digest = sign`
        let digest = Update::chain(sha2::Sha256::default(), &sighash);
        use ecdsa::signature::digest::FixedOutput;
        let digest = <[u8; 32]>::try_from(&*digest.finalize_fixed()).unwrap();
        let sig_two_step = secret_key.sign_digest(&digest).unwrap();
        if let SecretKey::K256(key) = &secret_key {
            if let Signature::K256(signature) = &sig_two_step {
                use ecdsa::signature::Verifier;
                let sig: k256::ecdsa::Signature = (*signature).into();
                println!("{:?}", &sig);
                assert!(key.verifying_key().verify(&sighash, &sig).is_ok());
            }
        }
        // This fails due to different ephemeral points
        let sig_one_step = secret_key.sign(&sighash).unwrap();
        assert_eq!(
            hex::encode(sig_one_step.raw_with_recovery().unwrap()),
            hex::encode(sig_two_step.raw_with_recovery().unwrap()),
        );
    }
}
