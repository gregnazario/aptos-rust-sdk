pub mod api_types;
// Replaced with other crypto
//pub mod crypto;
pub mod error;
pub mod headers;
pub mod mime_types;
pub mod serializable;
pub mod state;

use crate::error::RestError;

pub type AptosResult<T> = Result<T, RestError>;
