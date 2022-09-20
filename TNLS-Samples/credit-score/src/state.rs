use cosmwasm_std::{Binary, HumanAddr};
use secret_toolkit::storage::Item;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub static CONFIG: Item<State> = Item::new(b"config");

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct State {
    pub gateway_address: HumanAddr,
    pub gateway_hash: String,
    pub gateway_key: Binary,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Input {
    // user ethereum address
    pub address: String,
    // user name
    pub name: Option<String>,
    // financial information (all values in $USD)
    pub offchain_assets: u32,
    pub onchain_assets: u32,
    pub liabilities: u32,
    pub missed_payments: u32,
    pub income: u32,
}
