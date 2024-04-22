use crate::types::crypto::traits::Signature;
use anyhow::anyhow;
use ed25519_dalek::ed25519::SignatureBytes;
use std::cmp::Ordering;
use std::fmt::{Debug, Display, Formatter};

const L: [u8; 32] = [
    0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

#[derive(Clone)]
pub struct Ed25519Signature(ed25519_dalek::Signature);

impl Ed25519Signature {
    pub(crate) fn inner(&self) -> &ed25519_dalek::Signature {
        &self.0
    }
}

impl TryFrom<[u8; 64]> for Ed25519Signature {
    type Error = anyhow::Error;

    fn try_from(bytes: [u8; 64]) -> anyhow::Result<Self> {
        if !check_signature_canonical(&bytes[32..]) {
            return Err(anyhow! {"Non-canonical signature"});
        }

        Ok(Ed25519Signature(ed25519_dalek::Signature::from_bytes(
            &SignatureBytes::from(bytes),
        )))
    }
}

impl From<ed25519_dalek::Signature> for Ed25519Signature {
    fn from(signature: ed25519_dalek::Signature) -> Self {
        Ed25519Signature(signature)
    }
}

impl Signature for Ed25519Signature {}

impl Debug for Ed25519Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl Display for Ed25519Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0.to_bytes().as_slice()))
    }
}

pub fn check_signature_canonical(s: &[u8]) -> bool {
    for i in (0..32).rev() {
        match s[i].cmp(&L[i]) {
            Ordering::Less => return true,
            Ordering::Greater => return false,
            _ => {}
        }
    }
    // As this stage S == L which implies a non-canonical S.
    false
}

#[cfg(test)]
pub fn non_canonical_signature() -> [u8; 64] {
    let vec: Vec<u8> = vec![L, L].into_iter().flatten().collect();
    vec.try_into().unwrap()
}
