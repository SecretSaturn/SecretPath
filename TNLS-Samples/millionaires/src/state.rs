use std::cmp::Ordering;

use cosmwasm_std::{Binary, HumanAddr};
use secret_toolkit::storage::{Item, Keymap};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub static CONFIG: Item<State> = Item::new(b"config");
pub static MILLIONAIRES: Keymap<String, Millionaire> = Keymap::new(b"millionaires");

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct State {
    pub gateway_address: HumanAddr,
    pub gateway_hash: String,
    pub gateway_key: Binary,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Input {
    // user ethereum address
    pub address: String,
    // user name
    pub name: Option<String>,
    // user monies
    pub worth: u64,
    // the expected address to be match with
    pub match_addr: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq)]
pub struct Millionaire {
    pub name: String,
    pub worth: u64,
    pub match_addr: String,
}

impl Millionaire {
    /// Constructor function. Takes input parameters and initializes a struct containing the items
    pub fn new(name: String, worth: u64, match_addr: String) -> Millionaire {
        Millionaire { name, worth, match_addr }
    }
}

impl PartialOrd for Millionaire {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Millionaire {
    fn cmp(&self, other: &Self) -> Ordering {
        self.worth.cmp(&other.worth)
    }
}

impl PartialEq for Millionaire {
    fn eq(&self, other: &Self) -> bool {
        self.worth == other.worth
    }
}
