use cosmwasm_std::{Addr, Binary};
use secret_toolkit::utils::HandleCallback;
use secret_path::msg::{PostExecutionMsg, PrivContractHandleMsg};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    pub gateway_address: Addr,
    pub gateway_hash: String,
    pub gateway_key: Binary,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    Input { message: PrivContractHandleMsg }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InputStoreMsg {
    // Key of the StorageItem  
    pub key: String,
    // Value of the StorageItem  
    pub value: String,
    // ViewingKey of the StorageItem to unlock the value
    pub viewing_key: String,
    // Address who is allowed to unlock the StorageItem with a permit
    pub addresses: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ResponseStoreMsg {
    // Key of the StorageItem  
    pub key: String,
    // response message
    pub message: String
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InputRetrieveMsg {
    // Key of the StorageItem  
    pub key: String,
    // ViewingKey of the StorageItem to unlock the value
    pub viewing_key: String
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ResponseRetrieveMsg {
    // Key of the StorageItem  
    pub key: String,
    // value of the StorageItem  
    pub value: String,
    // response message
    pub message: String
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    RetrieveValue {key: String, viewing_key: String}
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct QueryResponse {
    pub message: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GatewayMsg {
    Output { outputs: PostExecutionMsg },
}

impl HandleCallback for GatewayMsg {
    const BLOCK_SIZE: usize = 256;
}
