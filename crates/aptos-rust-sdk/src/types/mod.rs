pub mod error;
pub mod headers;
pub mod mime_types;
pub mod state;
//pub mod api_types;
pub mod api_types;
pub mod crypto;

use crate::types::error::RestError;

pub type AptosResult<T> = Result<T, RestError>;
