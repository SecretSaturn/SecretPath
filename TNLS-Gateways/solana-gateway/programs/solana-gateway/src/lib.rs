use anchor_lang::prelude::*;
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    program_error::ProgramError,
    pubkey::Pubkey,
    msg,
};
use solana_program::keccak::hash;
use solana_program::keccak::Hasher;
use solana_program::program_pack::{IsInitialized, Pack, Sealed};
use borsh::{BorshDeserialize, BorshSerialize};


// Constants
const TASK_DESTINATION_NETWORK: &str = "pulsar-3";
const SECRET_GATEWAY_SIGNER_ADDRESS: &str = "2821E794B01ABF0cE2DA0ca171A1fAc68FaDCa06";

#[program]
pub mod solana_gateway {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        Ok(())
    }
    #[derive(BorshDeserialize, BorshSerialize, Debug, PartialEq)]
pub struct Task {
    payload_hash_reduced: [u8; 31],
    completed: bool,
}

#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub struct ExecutionInfo {
    user_key: Vec<u8>,
    user_pubkey: Vec<u8>,
    routing_code_hash: String,
    task_destination_network: String,
    handle: String,
    nonce: [u8; 12],
    callback_gas_limit: u32,
    payload: Vec<u8>,
    payload_signature: Vec<u8>,
}

#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub struct PostExecutionInfo {
    payload_hash: [u8; 32],
    packet_hash: [u8; 32],
    callback_address: [u8; 20],
    callback_selector: [u8; 4],
    callback_gas_limit: [u8; 4],
    packet_signature: Vec<u8>,
    result: Vec<u8>,
}

#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub struct GatewayState {
    task_id: u32,
    tasks: Vec<Task>,
}

impl Sealed for GatewayState {}
impl IsInitialized for GatewayState {
    fn is_initialized(&self) -> bool {
        self.task_id > 0
    }
}

// Entry point for the Solana program
entrypoint!(process_instruction);
fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let state_account = next_account_info(account_info_iter)?;
    let mut state = GatewayState::try_from_slice(&state_account.data.borrow())?;

    let task_id = state.task_id;

    // Emitting events would differ on Solana, but you could log messages as events
    msg!(
        "logNewTask: task_id: {}, source_network: {}, user_address: {}, routing_info: {}, payload_hash: {:?}, ExecutionInfo",
        task_id,
        CHAIN_ID,
        TASK_DESTINATION_NETWORK,
        VRF_ROUTING_INFO,
        hash(instruction_data)
    );

    // Update state
    state.task_id += 1;
    state.serialize(&mut *state_account.data.borrow_mut())?;

    Ok(())
}
}

#[derive(Accounts)]
pub struct Initialize {}

