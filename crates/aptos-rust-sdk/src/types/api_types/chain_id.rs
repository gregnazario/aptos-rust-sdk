use std::str::FromStr;
use serde::{Deserialize, Deserializer, Serializer};
use serde_bytes::Serialize;

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum ChainId {
    Mainnet,
    Testnet,
    Testing,
    Other(u8),
}

const MAINNET: &str = "mainnet";
const TESTNET: &str = "testnet";
const TESTING: &str = "testing";

impl Serialize for ChainId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        match self {
            ChainId::Mainnet => serializer.serialize_str(MAINNET),
            ChainId::Testnet => serializer.serialize_str(TESTNET),
            ChainId::Testing => serializer.serialize_str(TESTING),
            ChainId::Other(inner) => serializer.serialize_str(&inner.to_string()),
        }
    }
}

impl<'de> Deserialize<'de> for ChainId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        let str = String::deserialize(deserializer)?;
        Ok(match &str {
            MAINNET => ChainId::Mainnet,
            TESTNET => ChainId::Testnet,
            TESTING => ChainId::Testing,
            other => ChainId::Other(u8::from_str(other)?)
        })
    }
}