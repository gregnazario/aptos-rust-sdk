use tiny_keccak::{Hasher, Sha3};

/// A prefix used to begin the salt of every hashable structure. The salt
/// consists in this global prefix, concatenated with the specified
/// serialization name of the struct.
pub(crate) const HASH_PREFIX: &[u8] = b"APTOS::";
pub const HASH_LENGTH: usize = 32;

/// Output value of our hash function. Intentionally opaque for safety and modularity.
#[derive(Clone, Copy, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct HashValue([u8; HASH_LENGTH]);

impl HashValue {
    pub const fn zero() -> Self {
        HashValue([0; HASH_LENGTH])
    }

    pub fn sha3_256(input: &[u8]) -> HashValue {
        let mut hasher = Sha3::v256();
        hasher.update(input);

        let mut bytes = [0u8; 32];
        hasher.finalize(&mut bytes);
        HashValue(bytes)
    }

    pub fn as_slice(&self) -> &[u8; 32] {
        &self.0
    }
}
