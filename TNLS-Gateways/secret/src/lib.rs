//! # Master Private Gateway
//!
//! ## Example Usage
//!
//! ```rust,ignore
//! // TBD
//! ```
//!
//! ### Cargo Features
//!
//! * `contract`: enables init/handle/query exports (default)
//!     - use `default-features: false` to use this package as a dependency instead of a contract
pub mod contract;
pub mod msg;
pub mod state;
pub mod types;

pub use crate::msg::{
    InputResponse, PostExecutionMsg, PreExecutionMsg, PrivContractHandleMsg,
    ResponseStatus::Success,
};
pub use crate::types::Payload;
