use serde::{Deserialize, Serialize};
use crate::api_types::address::AccountAddress;
use crate::api_types::identifier::Identifier;

/// Represents the initial key into global storage where we first index by the address, and then
/// the struct tag. The struct fields are public to support pattern matching.
#[derive(Serialize, Deserialize, Debug, PartialEq, Hash, Eq, Clone, PartialOrd, Ord)]
pub struct ModuleId {
    pub address: AccountAddress,
    pub name: Identifier,
}

impl From<ModuleId> for (AccountAddress, Identifier) {
    fn from(module_id: ModuleId) -> Self {
        (module_id.address, module_id.name)
    }
}

impl ModuleId {
    pub fn new(address: AccountAddress, name: Identifier) -> Self {
        ModuleId { address, name }
    }

    pub fn name(&self) -> &Identifier {
        &self.name
    }

    pub fn address(&self) -> &AccountAddress {
        &self.address
    }
}