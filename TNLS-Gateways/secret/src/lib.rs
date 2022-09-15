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

#[cfg(feature = "contract")]
#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::contract;
    use cosmwasm_std::{
        do_handle, do_init, do_query, ExternalApi, ExternalQuerier, ExternalStorage,
    };

    #[no_mangle]
    extern "C" fn init(env_ptr: u32, msg_ptr: u32) -> u32 {
        do_init(
            &contract::init::<ExternalStorage, ExternalApi, ExternalQuerier>,
            env_ptr,
            msg_ptr,
        )
    }

    #[no_mangle]
    extern "C" fn handle(env_ptr: u32, msg_ptr: u32) -> u32 {
        do_handle(
            &contract::handle::<ExternalStorage, ExternalApi, ExternalQuerier>,
            env_ptr,
            msg_ptr,
        )
    }

    #[no_mangle]
    extern "C" fn query(msg_ptr: u32) -> u32 {
        do_query(
            &contract::query::<ExternalStorage, ExternalApi, ExternalQuerier>,
            msg_ptr,
        )
    }

    // Other C externs like cosmwasm_vm_version_1, allocate, deallocate are available
    // automatically because we `use cosmwasm_std`.
}
