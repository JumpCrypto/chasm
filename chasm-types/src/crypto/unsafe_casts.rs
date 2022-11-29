//! Age goes out of its way to hide the content of its newtype
//! Identity(x25519_dalek::StaticSecret)
//!
//! For us, it doesn't make sense to have two types for the same algorithm,
//! we definitely want `age` for imports and possibly recipient serialization format,
//! but not for the secret keys and signature formats.
//!
//! Maybe there's a better way to do this.

use std::mem;

use super::{
    AgeX255PublicKey,
    X255PublicKey,
    AgeX255SecretKey,
    X255SecretKey,
};


// pub(crate) fn sk_age_to_x255(age: AgeX255SecretKey) -> X255SecretKey {
//     unsafe { mem::transmute(age) }
// }

// fn sk_x255_to_age(x255: X255SecretKey) -> AgeX255SecretKey {
//     unsafe { mem::transmute(x255) }
// }

pub fn sk_ref_x255_to_age(x255: &X255SecretKey) -> &AgeX255SecretKey {
    unsafe { mem::transmute(x255) }
}

// fn pk_age_to_x255(age: AgeX255PublicKey) -> X255PublicKey {
//     unsafe { mem::transmute(age) }
// }

pub fn pk_x255_to_age(x255: X255PublicKey) -> AgeX255PublicKey {
    unsafe { mem::transmute(x255) }
}

