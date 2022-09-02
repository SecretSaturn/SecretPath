use cosmwasm_std::{Binary, CanonicalAddr, Storage};
use cosmwasm_storage::{singleton, singleton_read, ReadonlySingleton, Singleton};
use secret_toolkit::incubator::{CashMap, ReadOnlyCashMap};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Storage key for this contract's configuration.
pub const CONFIG_KEY: &[u8] = b"config";
/// Storage key for this contract's address.
pub const MY_ADDRESS_KEY: &[u8] = b"myaddr";
/// Storage key for the contract instantiator.
pub const CREATOR_KEY: &[u8] = b"creator";
/// Storage key for prng seed.
pub const PRNG_SEED_KEY: &[u8] = b"prngseed";
/// Storage key for task IDs.
pub const TASK_KEY: &[u8] = b"tasks";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct State {
    /// Admin adress.
    pub admin: CanonicalAddr,
    /// Status of gateway key generation.
    pub keyed: bool,
    /// Count of tx.
    pub tx_cnt: u64,
    /// Contract status.
    pub status: u8,
    /// Private gateway encryption key pair.
    pub encryption_keys: KeyPair,
    /// Private gateway signing key pair.
    pub signing_keys: KeyPair,
}

/// A key pair using the [Binary] type
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema, Default)]
pub struct KeyPair {
    /// Secret key part of the key pair.
    pub sk: Binary,
    /// Public key part of the key pair.
    pub pk: Binary,
}

/// Access storage for this contract's configuration.
pub fn config<S: Storage>(storage: &mut S) -> Singleton<S, State> {
    singleton(storage, CONFIG_KEY)
}
/// Access read-only storage for this contract's configuration.
pub fn config_read<S: Storage>(storage: &S) -> ReadonlySingleton<S, State> {
    singleton_read(storage, CONFIG_KEY)
}

/// Access PRNG seed storage.
pub fn prng<S: Storage>(storage: &mut S) -> Singleton<S, Vec<u8>> {
    singleton(storage, PRNG_SEED_KEY)
}
/// Access read-only PRNG seed storage.
pub fn prng_read<S: Storage>(storage: &S) -> ReadonlySingleton<S, Vec<u8>> {
    singleton_read(storage, PRNG_SEED_KEY)
}

/// Access storage for this contract's address.
pub fn my_address<S: Storage>(storage: &mut S) -> Singleton<S, CanonicalAddr> {
    singleton(storage, MY_ADDRESS_KEY)
}
/// Access read-only storage for this contract's address.
pub fn my_address_read<S: Storage>(storage: &mut S) -> Singleton<S, CanonicalAddr> {
    singleton(storage, MY_ADDRESS_KEY)
}

/// Access storage for the contract creator's address.
pub fn creator_address<S: Storage>(storage: &mut S) -> Singleton<S, CanonicalAddr> {
    singleton(storage, MY_ADDRESS_KEY)
}
/// Access read-only storage for the contract creator's address.
pub fn creator_address_read<S: Storage>(storage: &mut S) -> Singleton<S, CanonicalAddr> {
    singleton(storage, MY_ADDRESS_KEY)
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct TaskInfo {
    /// Encryption of (data, routing info, and user address/verifying key).
    pub payload: Binary,
    /// sha256(decrypted input_values)
    pub input_hash: [u8; 32],
    /// Source network (where to go once pulled into the next gateway).
    pub source_network: String,
}

// Cashmap is convenient, but may not be the best solution if we need to maintain an ordered list
pub fn map2inputs<S: Storage>(storage: &mut S) -> CashMap<TaskInfo, S> {
    let hashmap: CashMap<TaskInfo, S> = CashMap::init(TASK_KEY, storage);
    hashmap
}

pub fn map2inputs_read<S: Storage>(storage: &S) -> ReadOnlyCashMap<TaskInfo, S> {
    let hashmap: ReadOnlyCashMap<TaskInfo, S> = ReadOnlyCashMap::init(TASK_KEY, storage);
    hashmap
}
