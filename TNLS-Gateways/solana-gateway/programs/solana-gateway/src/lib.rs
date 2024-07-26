use anchor_lang::{
    prelude::*,
    solana_program::{
        instruction::Instruction,
        program::invoke_signed,
        secp256k1_recover::{secp256k1_recover, Secp256k1Pubkey},
        sysvar::{rent::Rent, Sysvar},
    },
    system_program::{transfer, Transfer},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use hex::decode;
use sha3::{Digest, Keccak256};
use std::str::FromStr;

pub mod errors;
use crate::errors::{GatewayError, ProgramError, TaskError};

declare_id!("5LWZAN7ZFE3Rmg4MdjqNTRkSbMxthyG8ouSa3cfn3R6V");

// Constants

const TASK_DESTINATION_NETWORK: &str = "pulsar-3";
const CHAIN_ID: &str = "SolanaDevNet";
const SECRET_GATEWAY_PUBKEY: &str =
    "0x04f0c3e600c7f7b3c483debe8f98a839c2d93230d8f857b3c298dc8763c208afcd62dcb34c9306302bf790d8c669674a57defa44c6a95b183d94f2e645526ffe5e";

const SEED: &[u8] = b"gateway_state";

#[program]
mod solana_gateway {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let gateway_state = &mut ctx.accounts.gateway_state;

        // Verify that the gateway_state is a PDA with the correct seeds and bump
        let (expected_gateway_state, _bump_seed) =
            Pubkey::find_program_address(&[SEED.as_ref()], ctx.program_id);

        require!(
            gateway_state.key() == expected_gateway_state,
            GatewayError::InvalidGatewayState
        );

        // Check if the gateway_state has already been initialized

        require!(
            gateway_state.owner == Pubkey::default(),
            GatewayError::PDAAlreadyInitialized
        );

        gateway_state.owner = *ctx.accounts.owner.key;
        gateway_state.task_id = 0;
        gateway_state.tasks = Vec::new();
        gateway_state.max_tasks = 10;

        Ok(())
    }

    pub fn increase_task_id(ctx: Context<IncreaseTaskId>, new_task_id: u64) -> Result<()> {
        let gateway_state = &mut ctx.accounts.gateway_state;

        // Verify that the gateway_state is a PDA with the correct seeds and bump
        let (expected_gateway_state, _bump_seed) =
            Pubkey::find_program_address(&[SEED.as_ref()], ctx.program_id);

        require!(
            gateway_state.key() == expected_gateway_state,
            GatewayError::InvalidGatewayState
        );

        require!(
            new_task_id > gateway_state.task_id,
            GatewayError::TaskIdTooLow
        );

        gateway_state.task_id = new_task_id;
        Ok(())
    }

    pub fn send(
        ctx: Context<Send>,
        user_address: Pubkey,
        routing_info: String,
        execution_info: ExecutionInfo,
    ) -> Result<SendResponse> {
        let gateway_state = &mut ctx.accounts.gateway_state;

        // Verify that the gateway_state is a PDA with the correct seeds and bump
        let (expected_gateway_state, _bump_seed) =
            Pubkey::find_program_address(&[SEED.as_ref()], ctx.program_id);

        require!(
            gateway_state.key() == expected_gateway_state,
            GatewayError::InvalidGatewayState
        );

        // Fetch the current lamports per signature cost for the singature
        let lamports_per_signature = 10;

        // //Calculate the rent for extra storage
        let lamports_per_byte_year = Rent::get().unwrap().lamports_per_byte_year;

        // // Estimate the cost based on the callback gas limit
        let estimated_price = execution_info.callback_gas_limit as u64 * lamports_per_signature
            + (std::mem::size_of::<Task>() as u64 * 2 * lamports_per_byte_year);

        let user_lamports = ctx.accounts.user.lamports();

        require!(
            user_lamports >= estimated_price,
            TaskError::InsufficientFunds
        );

        let cpi_accounts = Transfer {
            from: ctx.accounts.user.to_account_info(),
            to: gateway_state.to_account_info(),
        };

        let cpi_context =
            CpiContext::new(ctx.accounts.system_program.to_account_info(), cpi_accounts);

        transfer(cpi_context, estimated_price)?;

        //Hash the payload
        let generated_payload_hash =
            solana_program::keccak::hash(&execution_info.payload).to_bytes();

        // Persist the task
        let task = Task {
            payload_hash: generated_payload_hash,
            task_id: gateway_state.task_id,
            completed: false,
        };

        // Calculate the array index
        let index = (gateway_state.task_id % gateway_state.max_tasks) as usize;

        // Reallocate account space if necessary
        if index >= gateway_state.tasks.len() {
            if gateway_state.tasks.len() >= gateway_state.max_tasks as usize {
                let new_max_tasks = gateway_state.max_tasks + 10;
                let new_space = 8 + 8 + 8 + (std::mem::size_of::<Task>() as u64 * new_max_tasks);
                gateway_state
                    .to_account_info()
                    .realloc(new_space.try_into().unwrap(), false)?;
                gateway_state.max_tasks = new_max_tasks;
            }

            // If the array isn't filled up yet, just push it to the end
            gateway_state.tasks.push(task);
        } else {
            // If a task already exists, it will be overwritten as expected from the max.
            gateway_state.tasks[index] = task;
        }

        let task_id = gateway_state.task_id;

        let log_new_task = LogNewTask {
            task_id: task_id,
            source_network: CHAIN_ID.to_string(),
            user_address: user_address.to_bytes().to_vec(),
            routing_info: routing_info,
            payload_hash: generated_payload_hash,
            user_key: execution_info.user_key,
            user_pubkey: execution_info.user_pubkey,
            routing_code_hash: execution_info.routing_code_hash,
            task_destination_network: TASK_DESTINATION_NETWORK.to_string(),
            handle: execution_info.handle,
            nonce: execution_info.nonce,
            callback_gas_limit: execution_info.callback_gas_limit,
            payload: execution_info.payload,
            payload_signature: execution_info.payload_signature,
        };

        msg!(&format!(
            "LogNewTask:{}",
            STANDARD.encode(&log_new_task.try_to_vec().unwrap())
        ));

        gateway_state.task_id += 1;

        Ok(SendResponse {
            request_id: task_id,
        })
    }

    pub fn post_execution<'info>(
        ctx: Context<'_, '_, '_, 'info, PostExecution<'info>>,
        task_id: u64,
        source_network: String,
        post_execution_info: PostExecutionInfo,
    ) -> Result<()> {
        let gateway_state = &mut ctx.accounts.gateway_state;

        // Verify that the gateway_state is a PDA with the correct seeds and bump
        let (expected_gateway_state, bump_seed) =
            Pubkey::find_program_address(&[SEED.as_ref()], ctx.program_id);

        require!(
            gateway_state.key() == expected_gateway_state,
            GatewayError::InvalidGatewayState
        );

        let index = (task_id % gateway_state.max_tasks) as usize;

        require!(index <= gateway_state.tasks.len(), TaskError::InvalidIndex);

        let task = &gateway_state.tasks[index];

        require!(task_id == task.task_id, TaskError::TaskIdAlreadyPruned);

        // Check if the task is already completed
        require!(!task.completed, TaskError::TaskAlreadyCompleted);

        // Concatenate packet data elements,
        // use saved in contract payload_hash to verify that the payload hash wasn't manipulated
        let data = [
            source_network.as_bytes(),
            CHAIN_ID.as_bytes(),
            task_id.to_string().as_bytes(),
            task.payload_hash.as_slice(),
            post_execution_info.result.as_slice(),
            post_execution_info.callback_address.as_slice(),
            post_execution_info.callback_selector.as_slice(),
        ]
        .concat();

        let mut hasher = Keccak256::new();
        hasher.update(&data);
        let keccak_hash = hasher.finalize_reset();

        let packet_hash = solana_program::hash::hash(&keccak_hash);

        // Packet hash verification
        require!(
            packet_hash.to_bytes().as_slice() == post_execution_info.packet_hash,
            TaskError::InvalidPacketHash
        );

        // Decode the base64 public key
        let pubkey_hex = &SECRET_GATEWAY_PUBKEY[2..];

        // Convert the hex string to bytes
        let pubkey_bytes = decode(pubkey_hex).map_err(|_| TaskError::InvalidPublicKey)?;
        let expected_pubkey = Secp256k1Pubkey::new(&pubkey_bytes[1..]);

        // Extract the recovery ID and signature from the packet signature
        // RecoveryID here might me 27, 28 due to the ethereum bug

        let recovery_id = match post_execution_info.packet_signature[64].checked_sub(27) {
            Some(id) if id == 0 || id == 1 => id,
            _ => return Err(TaskError::InvalidPacketSignature.into()),
        };

        // Perform the signature recovery
        let recovered_pubkey = secp256k1_recover(
            &post_execution_info.packet_hash,
            recovery_id,
            &post_execution_info.packet_signature[..64],
        )
        .map_err(|_| TaskError::Secp256k1RecoverFailure)?;

        // // Verify that the recovered public key matches the expected public key
        require!(
            recovered_pubkey == expected_pubkey,
            TaskError::InvalidPacketSignature
        );

        // Mark the task as completed
        gateway_state.tasks[index].completed = true;

        let callback_data = CallbackData {
            task_id: task_id,
            result: post_execution_info.result.clone(),
        };

        let borsh_data = callback_data
            .try_to_vec()
            .map_err(|_| TaskError::BorshDataSerializationFailed)?;

        // Verify that the recovered public key matches the expected public key
        require!(
            post_execution_info.callback_selector.len() == 40,
            TaskError::InvalidCallbackSelector
        );

        // Extract and concatenate the program ID and function identifier
        let (program_id_bytes, function_identifier) =
            post_execution_info.callback_selector.split_at(32);

        // Concatenate the function identifier with the rest of the data
        let mut callback_data = Vec::with_capacity(8 + borsh_data.len());
        callback_data.extend_from_slice(&function_identifier[0..8]);
        callback_data.extend_from_slice(&borsh_data);

        // Concatenate all addresses that will be accessed
        let callback_address_bytes = post_execution_info.callback_address.clone();

        require!(
            callback_address_bytes.len() % 32 == 0,
            TaskError::InvalidCallbackAddresses
        );

        let mut callback_account_metas = Vec::new();
        let mut callback_addresses = Vec::new();

        // Add the PDA as the signer
        // Modify the AccountInfo to set is_writable to false for gateway_state
        let mut gateway_state_account_info = ctx.accounts.gateway_state.to_account_info();
        gateway_state_account_info.is_writable = false;
        gateway_state_account_info.is_signer = true;
        callback_account_metas.push(AccountMeta::new_readonly(expected_gateway_state, true));
        callback_addresses.push(gateway_state_account_info);

        // Add the system_program account
        callback_account_metas.push(AccountMeta::new_readonly(
            *ctx.accounts.system_program.key,
            false,
        ));
        callback_addresses.push(ctx.accounts.system_program.to_account_info());

        let mut found_addresses = std::collections::HashSet::new();

        for chunk in callback_address_bytes.chunks(32) {
            match Pubkey::try_from(chunk) {
                Ok(pubkey) => {
                    if pubkey == expected_gateway_state {
                        continue;
                    }

                    if ctx
                        .remaining_accounts
                        .iter()
                        .any(|account| account.key == &pubkey)
                    {
                        if found_addresses.insert(pubkey) {
                            if let Some(account) = ctx
                                .remaining_accounts
                                .iter()
                                .find(|account| account.key == &pubkey)
                            {
                                callback_account_metas
                                    .push(AccountMeta::new(*account.key, account.is_signer));
                                callback_addresses.push(account.clone());
                            } else {
                                return Err(TaskError::InvalidCallbackAddresses.into());
                            }
                        }
                    } else {
                        return Err(TaskError::MissingRequiredSignature.into());
                    }
                }
                Err(_) => return Err(TaskError::InvalidCallbackAddresses.into()),
            }
        }

        // Execute the callback with signed seeds
        let callback_result = invoke_signed(
            &Instruction {
                program_id: Pubkey::try_from(program_id_bytes).expect("Invalid Pubkey"),
                accounts: callback_account_metas,
                data: callback_data,
            },
            &callback_addresses,
            &[&[SEED.as_ref(), &[bump_seed]]],
        );

        // Emit Message that the task was completed and if it returned Ok
        msg!(
            "TaskCompleted: task_id: {} and callback_result: {}",
            task_id,
            callback_result.is_ok()
        );

        Ok(())
    }

    pub fn callback_test(ctx: Context<CallbackTest>, task_id: u64, result: Vec<u8>) -> Result<()> {
        // Check if the callback is really coming from the secretpath_gateway and that it was signed by it
        const SECRET_PATH_ADDRESS: &str = "5mf563g8JSeTE1mMY4GSqbynjayToKSh7x5WLoQ9RDEQ";
        let secretpath_address_pubkey =
            Pubkey::from_str(SECRET_PATH_ADDRESS).expect("Invalid public key format");

        // Inline check for signature and address
        if !ctx.accounts.secretpath_gateway.is_signer
            || ctx.accounts.secretpath_gateway.key() != secretpath_address_pubkey
        {
            msg!("Callback failed: Invalid signer or public key mismatch");
            return Err(ProgramError::InvalidSecretPathGateway.into());
        }

        // Convert result to base64 string for test purposes
        msg!(
            "Callback invoked with task_id: {} and result: {}",
            task_id,
            STANDARD.encode(&result)
        );

        Ok(())
    }
}

#[derive(Accounts)]
pub struct CallbackTest<'info> {
    #[account()]
    pub secretpath_gateway: Signer<'info>,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = owner,
        space = 8 + 1024,
        seeds = [SEED],
        bump
    )]
    pub gateway_state: Account<'info, GatewayState>,
    #[account(mut, signer)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct IncreaseTaskId<'info> {
    #[account(mut, seeds = [SEED], bump)]
    pub gateway_state: Account<'info, GatewayState>,
    #[account(mut, signer)]
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct Send<'info> {
    #[account(mut, seeds = [SEED], bump)]
    pub gateway_state: Account<'info, GatewayState>,
    #[account(mut, signer)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct PostExecution<'info> {
    #[account(mut, seeds = [SEED], bump)]
    pub gateway_state: Account<'info, GatewayState>,
    #[account(mut, signer)]
    pub signer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct GatewayState {
    pub owner: Pubkey,
    pub task_id: u64,
    pub tasks: Vec<Task>,
    pub max_tasks: u64,
}

#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct Task {
    pub payload_hash: [u8; 32],
    pub task_id: u64,
    pub completed: bool,
}

#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct ExecutionInfo {
    pub user_key: Vec<u8>,
    pub user_pubkey: Vec<u8>,
    pub routing_code_hash: String,
    pub task_destination_network: String,
    pub handle: String,
    pub nonce: Vec<u8>,
    pub callback_gas_limit: u32,
    pub payload: Vec<u8>,
    pub payload_signature: Vec<u8>,
}

#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct PostExecutionInfo {
    pub packet_hash: [u8; 32],
    pub callback_address: Vec<u8>,
    pub callback_selector: Vec<u8>,
    pub callback_gas_limit: Vec<u8>,
    pub packet_signature: [u8; 65],
    pub result: Vec<u8>,
}

#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct CallbackData {
    task_id: u64,
    result: Vec<u8>,
}

#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct SendResponse {
    pub request_id: u64,
}

#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct LogNewTask {
    pub task_id: u64,
    pub source_network: String,
    pub user_address: Vec<u8>,
    pub routing_info: String,
    pub payload_hash: [u8; 32],
    pub user_key: Vec<u8>,
    pub user_pubkey: Vec<u8>,
    pub routing_code_hash: String,
    pub task_destination_network: String,
    pub handle: String,
    pub nonce: Vec<u8>,
    pub callback_gas_limit: u32,
    pub payload: Vec<u8>,
    pub payload_signature: Vec<u8>,
}
