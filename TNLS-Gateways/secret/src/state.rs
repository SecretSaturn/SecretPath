use cosmwasm_std::{Addr, Binary, CanonicalAddr};
use secret_toolkit::storage::{Item, Keymap};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Storage key for this contract's configuration.
pub static CONFIG: Item<State> = Item::new(b"config");
/// Storage key for this contract's address.
pub static MY_ADDRESS: Item<CanonicalAddr> = Item::new(b"myaddr");
/// Storage key for the contract instantiator.
pub static CREATOR: Item<CanonicalAddr> = Item::new(b"creator");
/// Storage key for task IDs.
pub static TASK_MAP: Keymap<Task, TaskInfo> = Keymap::new(b"tasks");
/// Storage key for task IDs.
pub static RESULT_MAP: Keymap<Task, ResultInfo> = Keymap::new(b"results");

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct State {
    /// Admin adress.
    pub admin: CanonicalAddr,
    /// Status of gateway key generation.
    pub keyed: bool,
    /// Count of tx.
    pub tx_cnt: u64,
    /// Private gateway encryption key pair.
    pub encryption_keys: KeyPair,
    /// Private gateway signing key pair.
    pub signing_keys: KeyPair,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Task {
    /// The network of the Task
    pub network: String,
    /// The task id of the test
    pub task_id: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct TaskInfo {
    /// The original, encrypted payload.
    pub payload: Binary,
    /// The original payload_hash from the front-end.
    pub payload_hash: Binary,
    /// The original payload_hash from the front-end.
    pub unsafe_payload: bool,
    /// A unique hash for the task.
    pub input_hash: [u8; 32],
    /// The name of the network that message came from.
    pub source_network: String,
    /// Public address of the user that sent the message.
    pub user_address: Addr,
    /// Callback address for the post execution message.
    pub callback_address: Binary,
    /// Callback selector for the post execution message.
    pub callback_selector: Binary,
    /// Callback gas limit for the post execution message.
    pub callback_gas_limit: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ResultInfo {
    /// The source network
    pub source_network: String,
    /// The task destination network
    pub task_destination_network: String,
    /// The task_id of the Result
    pub task_id: String,
    /// A unique hash for the task.
    pub payload_hash: String,
    /// The computation result
    pub result: String,
    /// The packet hash of the computed task
    pub packet_hash: String,
    /// Packet signature for the computed task
    pub packet_signature: String,
    /// Callback address for the post execution message.
    pub callback_address: String,
    /// Callback selector for the post execution message.
    pub callback_selector: String,
    /// Callback gas limit for the post execution message.
    pub callback_gas_limit: String,
}
/// A key pair using the [Binary] type
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema, Default)]
pub struct KeyPair {
    /// Secret key part of the key pair.
    pub sk: Binary,
    /// Public key part of the key pair.
    pub pk: Binary,
}
