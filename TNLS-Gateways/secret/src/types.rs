use cosmwasm_std::{Addr, Binary};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A packet containing user message data.
/// It is encrypted with a shared secret of the user's private key and the Private Gateway's public key.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Payload {
    /// Input values as JSON string.
    pub data: String,
    /// Destination contract address.
    pub routing_info: Addr,
    /// Destination contract code hash.
    pub routing_code_hash: String,
    /// User public chain address.
    pub user_address: Addr,
    /// User public key from payload encryption (not their wallet public key).
    pub user_key: Binary,
}
