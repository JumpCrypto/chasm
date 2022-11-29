/// Convert the looseness of protobufs into proper requests we can respond to.

use crate::{
    crypto::{Error, Result},
    api::{
        Id, NonZeroU32, Re, RequestId,
        request::{
            GenerateKey,
            DeriveChildKey,
            KeyMeta,
            ChildMeta,
            Sign,
            SignatureMeta,
            // ListKeys,
            ThresholdMeta,
            UnwrapKey,
            WrappedKeyData,
        },
    },
};

use super::chasm as proto;

impl Id for proto::PendingGenerateKey {
    fn id(&self) -> RequestId {
        self.re.as_ref().map(|re| re.name.clone()).unwrap_or_else(|| "missing request ID".into())
    }
}

impl Id for proto::PendingDeriveChildKey {
    fn id(&self) -> RequestId {
        self.re.as_ref().map(|re| re.name.clone()).unwrap_or_else(|| "missing request ID".into())
    }
}

impl Id for proto::PendingUnwrapKey {
    fn id(&self) -> RequestId {
        self.re.as_ref().map(|re| re.name.clone()).unwrap_or_else(|| "missing request ID".into())
    }
}

impl Id for proto::PendingSign {
    fn id(&self) -> RequestId {
        self.re.as_ref().map(|re| re.name.clone()).unwrap_or_else(|| "missing request ID".into())
    }
}

impl TryFrom<&proto::Re> for Re {
    type Error = Error;
    fn try_from(re: &proto::Re) -> Result<Re> {
        Ok(Self {
            name: re.name.to_string(),
            at: re.at,
        })
    }
}

impl From<&Re> for proto::Re {
    fn from(re: &Re) -> proto::Re {
        proto::Re {
            name: re.name.clone(),
            at: re.at,
        }
    }
}


impl TryFrom<&proto::KeyMeta> for KeyMeta {
    type Error = Error;
    fn try_from(meta: &proto::KeyMeta) -> Result<KeyMeta> {
        // TODO: fix after changing proto in x/chasm
        let l = meta.participants.len() as u32;
        let threshold = if l > 0 {
            let participants: Vec<NonZeroU32> = meta.participants.iter()
                .map(|&participant| NonZeroU32::new(participant))
                .collect::<Option<Vec<NonZeroU32>>>()
                .ok_or(Error::InvalidParticipants(meta.participants.clone()))?;
            if meta.threshold > l {
                return Err(Error::InvalidThreshold(meta.threshold));
            };
            let threshold = NonZeroU32::new(meta.threshold)
                .ok_or(Error::InvalidThreshold(meta.threshold))?;
            Some(ThresholdMeta { participants, threshold })
        } else {
            if meta.threshold != 1 {
                return Err(Error::InvalidThreshold(meta.threshold));
            }
            None
        };

        Ok(Self {
            name: meta.name.to_string(),
            algorithm: meta.algorithm.try_into()?,
            threshold,
            format: meta.format.try_into()?,
        })
    }
}

impl TryFrom<&proto::PendingGenerateKey> for GenerateKey {
    type Error = Error;
    fn try_from(pending: &proto::PendingGenerateKey) -> Result<GenerateKey> {
        Ok(Self {
            re: pending.re.as_ref().ok_or(Error::IncompleteRequest)?.try_into()?,
            meta: pending.meta.as_ref().ok_or(Error::IncompleteRequest)?.try_into()?,
        })
    }
}

impl TryFrom<&proto::ChildMeta> for ChildMeta {
    type Error = Error;
    fn try_from(meta: &proto::ChildMeta) -> Result<ChildMeta> {
        Ok(Self {
            name: meta.name.to_string(),
            parent: meta.parent.to_string(),
            child: meta.child,
            chain_code: None,
            format: meta.format.try_into()?,
        })
    }
}

impl TryFrom<&proto::PendingDeriveChildKey> for DeriveChildKey {
    type Error = Error;
    fn try_from(pending: &proto::PendingDeriveChildKey) -> Result<DeriveChildKey> {
        Ok(Self {
            re: pending.re.as_ref().ok_or(Error::IncompleteRequest)?.try_into()?,
            meta: pending.meta.as_ref().ok_or(Error::IncompleteRequest)?.try_into()?,
        })
    }
}

impl TryFrom<&proto::WrappedKeyData> for WrappedKeyData {
    type Error = Error;
    fn try_from(data: &proto::WrappedKeyData) -> Result<WrappedKeyData> {
        Ok(Self {
            wrapping_key: data.wrapping_key.to_string(),
            format: data.format.try_into()?,
            wrapped_key: data.wrapped_key.clone(),
        })
    }
}

impl TryFrom<&proto::PendingUnwrapKey> for UnwrapKey {
    type Error = Error;
    fn try_from(pending: &proto::PendingUnwrapKey) -> Result<UnwrapKey> {
        Ok(Self {
            re: pending.re.as_ref().ok_or(Error::IncompleteRequest)?.try_into()?,
            meta: pending.meta.as_ref().ok_or(Error::IncompleteRequest)?.try_into()?,
            data: pending.wrapped_data.as_ref().ok_or(Error::IncompleteRequest)?.try_into()?,
        })
    }
}

impl TryFrom<&proto::SignatureMeta> for SignatureMeta {
    type Error = Error;
    fn try_from(meta: &proto::SignatureMeta) -> Result<SignatureMeta> {
        let l = meta.participants.len() as u32;
        let participants = if l > 0 {
            let participants: Vec<NonZeroU32> = meta.participants.iter()
                .map(|&participant| NonZeroU32::new(participant))
                .collect::<Option<Vec<NonZeroU32>>>()
                .ok_or(Error::InvalidParticipants(meta.participants.clone()))?;
            Some(participants)
        } else {
            None
        };
        Ok(Self {
            name: meta.name.to_string(),
            key: meta.key.to_string(),
            precomputed: None,
            participants,
            data: (meta.data.as_ref(), meta.prehashed).try_into()?,
            format: meta.format.try_into()?,
        })
    }
}

impl TryFrom<&proto::PendingSign> for Sign {
    type Error = Error;
    fn try_from(pending: &proto::PendingSign) -> Result<Sign> {
        Ok(Self {
            re: pending.re.as_ref().ok_or(Error::IncompleteRequest)?.try_into()?,
            meta: pending.meta.as_ref().ok_or(Error::IncompleteRequest)?.try_into()?,
        })
    }
}

