use cosmwasm_std::{from_binary, Addr, Binary, DepsMut, StdError, StdResult};
use secret_toolkit::utils::HandleCallback;

use crate::types::*;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use secp256k1::{ecdh::SharedSecret, PublicKey, SecretKey};
use crate::state::Task;

use base64::{engine::general_purpose, Engine};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    /// Optional admin address, info.sender if missing.
    pub admin: Option<Addr>
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    /// Process an interchain message through the private gateway.
    Input { inputs: PreExecutionMsg },
    /// Receive results from private contract and broadcast logs for Relayer.
    Output { outputs: PostExecutionMsg },
    /// Rotates the gateway keys, only callable by admin.
    RotateGatewayKeys {},
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Success,
    Failure,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct InputResponse {
    pub status: ResponseStatus,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// Query the gateway's public keys.
    GetPublicKeys {},
    GetExecutionResult {task: Task}
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct PublicKeyResponse {
    /// Base64 encoded string.
    pub encryption_key: Binary,
    /// '0x' prefixed hex encoded byte string.
    pub verification_key: String,
}

/// Message received from the relayer.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct PreExecutionMsg {
    /// Task ID generated by the public gateway.
    pub task_id: String,
    /// Source network (where to go once pulled into the next gateway).
    pub source_network: String,
    /// Destination contract address.
    pub routing_info: Addr,
    /// Destination contract code hash.
    pub routing_code_hash: String,
    /// Encryption of (data, routing info, and user info).
    pub payload: Binary,
    /// Hash of encrypted input values.
    pub payload_hash: Binary,
    /// Signature of hash of encrypted input values.
    pub payload_signature: Binary,
    /// User public chain address.
    pub user_address: Addr,
    /// User public key from payload encryption (not their wallet public key).
    pub user_key: Binary,
    /// User's wallet public key.
    pub user_pubkey: Binary,
    /// Handle to be called at destination contract.
    pub handle: String,
    /// Unique random bytes used to encrypt payload.
    pub nonce: Binary,
    /// Callback gas limit for the post execution message.
    pub callback_gas_limit: u32,
}

impl PreExecutionMsg {
    
    pub fn verify(&self, deps: &DepsMut) -> StdResult<()> {
        match deps.api.secp256k1_verify(
            self.payload_hash.as_slice(),
            self.payload_signature.as_slice(),
            self.user_pubkey.as_slice(),
        ) {
            Ok(_) => Ok(()),
            Err(_) => {
                deps.api.ed25519_verify(
                    general_purpose::STANDARD.encode(self.payload_hash.as_slice()).as_bytes(),
                    self.payload_signature.as_slice(),
                    self.user_pubkey.as_slice(),
                )
                .map_err(|err| StdError::generic_err(err.to_string()))
            }
        }
    }

    pub fn decrypt_payload(&self, sk: Binary) -> StdResult<Payload> {
        let my_secret = SecretKey::from_slice(sk.as_slice())
            .map_err(|err| StdError::generic_err(err.to_string()))?;

        let their_public = PublicKey::from_slice(self.user_key.as_slice())
            .map_err(|err| StdError::generic_err(err.to_string()))?;

        let shared_key = SharedSecret::new(&their_public, &my_secret);

        let cipher = ChaCha20Poly1305::new_from_slice(shared_key.as_ref())
            .map_err(|err| StdError::generic_err(err.to_string()))?;

        let nonce = Nonce::from_slice(self.nonce.as_slice());

        let plaintext = cipher
            .decrypt(nonce, self.payload.as_slice())
            .map(Binary)
            .map_err(|err| StdError::generic_err(err.to_string()))?;

        let payload: Payload = from_binary(&plaintext)?;

        Ok(payload)
    }
}

/// Messages sent to other secret contracts.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecretMsg {
    Input {
        message: PrivContractHandleMsg,
    },
}
impl HandleCallback for SecretMsg {
    const BLOCK_SIZE: usize = 256;
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct PrivContractHandleMsg {
    /// JSON string of decrypted user inputs.
    pub input_values: String,
    /// Handle function to be called in the destination contract.
    pub handle: String,
    /// Public network user address.
    pub user_address: Addr,
    /// Task passed along for later verification.
    pub task: Task,
    /// SHA256 hash of `input_values`.
    pub input_hash: Binary,
    /// Signature of `input_hash`, signed by the private gateway.
    pub signature: Binary,
}

/// Message received from destination private contract with results.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct PostExecutionMsg {
    /// JSON string of results from the private contract.
    pub result: String,
    /// Task from private contract for verification.
    pub task: Task,
    /// SHA256 of decrypted (inputs + task ID) for verification.
    pub input_hash: Binary,
}

impl HandleCallback for PostExecutionMsg {
    const BLOCK_SIZE: usize = 256;
}

/// Message sent to the relayer.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct BroadcastMsg {
    /// JSON string of results from the private contract.
    pub result: String,
    /// Encryption of (data, routing info, and user info).
    pub payload: Binary,
    /// Task ID coming from the gateway.
    pub task_id: String,
    /// SHA256 hash of (result, packet, task_id).
    pub output_hash: Binary,
    /// `output_hash` signed with Private Gateway key.
    pub signature: Binary,
    /// Source network (where to go once pulled into the next gateway).
    pub routing_info: String,
}

impl HandleCallback for BroadcastMsg {
    const BLOCK_SIZE: usize = 256;
}