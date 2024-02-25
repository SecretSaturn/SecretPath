use cosmwasm_std::{Addr, Binary};
use secret_toolkit::storage::Item;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub static CONFIG: Item<State> = Item::new(b"config");

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct State {
    pub gateway_address: Addr,
    pub gateway_hash: String,
    pub gateway_key: Binary,
}
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InputStore {
    // Number of Words to generate
    pub key: String,
    pub value: String,
    pub viewing_key: String
    pub address: String,
}
pub struct InputRetrieve {
    // Number of Words to generate
    pub key: String,
    pub viewing_key: String
}