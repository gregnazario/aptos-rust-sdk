use crate::crypto::traits::Signature;
use std::fmt::{Debug, Display, Formatter};

#[derive(Clone)]
pub struct Secp256k1Signature(libsecp256k1::Signature);

impl Secp256k1Signature {
    pub(crate) fn inner(&self) -> &libsecp256k1::Signature {
        &self.0
    }
}

impl TryFrom<&[u8; 64]> for Secp256k1Signature {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8; 64]) -> anyhow::Result<Self> {
        Ok(Secp256k1Signature(libsecp256k1::Signature::parse_standard(
            bytes,
        )?))
    }
}

impl From<libsecp256k1::Signature> for Secp256k1Signature {
    fn from(signature: libsecp256k1::Signature) -> Self {
        Secp256k1Signature(signature)
    }
}

impl Signature for Secp256k1Signature {}

impl Debug for Secp256k1Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl Display for Secp256k1Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0.serialize()))
    }
}
