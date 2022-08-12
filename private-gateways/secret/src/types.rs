use cosmwasm_std::{Binary, HumanAddr};
use secret_toolkit::utils::types::Contract;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Sender {
    /// User public chain address.
    pub address: HumanAddr,
    /// User verification key.
    pub public_key: Binary,
}

/// A packet containing user message data.
/// It is encrypted with a shared secret of the user's private key and the Private Gateway's public key.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Payload {
    /// Input values as JSON string.
    pub data: String,
    /// Destination contract on private network.
    pub routing_info: Contract,
    /// User verification key / public chain address.
    pub sender: Sender,
}
