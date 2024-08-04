use anchor_lang::{
    prelude::*,
    system_program
};
use base64::{engine::general_purpose::STANDARD, Engine};
use hex::decode;
use solana_program::{
    instruction::Instruction,
    program::invoke_signed,
    secp256k1_recover::secp256k1_recover
};
use solana_security_txt::security_txt;
use std::{
    cell::RefMut, str::FromStr
};

pub mod errors;
use crate::errors::{GatewayError, ProgramError, TaskError};

declare_id!("DKDX8XbTnCgEk8o1RNnCUokiCmadG1Ch5HLxaz7CnhcD");

#[cfg(not(feature = "no-entrypoint"))]
security_txt! {
    // Required fields
    name: "SecretPath",
    project_url: "https://github.com/SecretSaturn/SecretPath",
    contacts: "XXX",
    policy: "tbd",

    // Optional Fields
    preferred_languages: "en",
    auditors: "None",
    acknowledgements: ""
}

// Constants

const TASK_DESTINATION_NETWORK: &str = "pulsar-3";
const CHAIN_ID: &str = "SolanaDevNet";
const SECRET_GATEWAY_PUBKEY: &str =
    "0x04f0c3e600c7f7b3c483debe8f98a839c2d93230d8f857b3c298dc8763c208afcd62dcb34c9306302bf790d8c669674a57defa44c6a95b183d94f2e645526ffe5e";
const GATEWAY_SEED: &[u8] = b"gateway_state";
const TASK_SEED: &[u8] = b"task_state";
const LAMPORTS_PER_COMPUTE_UNIT: f64 = 0.1;

const MAX_TASKS: u64 = 8900;

#[program]
mod solana_gateway {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let gateway_state = &mut ctx.accounts.gateway_state;

        gateway_state.owner = *ctx.accounts.owner.key;

        gateway_state.task_id = 0;
        
        //Save the bump
        gateway_state.bump = ctx.bumps.gateway_state;

        Ok(())
    }

    pub fn increase_task_state(ctx: Context<IncreaseTaskState>, _len: u64) -> Result<()> {
        Ok(())
    }


    pub fn increase_task_id(ctx: Context<IncreaseTaskId>, new_task_id: u64) -> Result<()> {
        let gateway_state = &mut ctx.accounts.gateway_state;

        require!(
            new_task_id > gateway_state.task_id,
            GatewayError::TaskIdTooLow
        );

        gateway_state.task_id = new_task_id;
        Ok(())
    }

    pub fn payout_balance(ctx: Context<PayoutBalance>) -> Result<()> {
        let gateway_state = &mut ctx.accounts.gateway_state;

        let cpi_accounts = system_program::Transfer {
            from: gateway_state.to_account_info(),
            to: ctx.accounts.owner.to_account_info(),
        };

        let cpi_context =
            CpiContext::new(ctx.accounts.system_program.to_account_info(), cpi_accounts);

        system_program::transfer(
            cpi_context,
            ctx.accounts.gateway_state.to_account_info().lamports(),
        )?;

        Ok(())
    }

    pub fn send(
        ctx: Context<Send>,
        user_address: Pubkey,
        routing_info: String,
        execution_info: ExecutionInfo,
    ) -> Result<SendResponse> {
        let gateway_state = &mut ctx.accounts.gateway_state;

        // Use the current lamports per signature value of = 5000
        let lamports_per_signature = 5000;

        // Current cost on using CU = 0

        let estimated_price = (execution_info.callback_gas_limit as f64 * LAMPORTS_PER_COMPUTE_UNIT)
            as u64
            + lamports_per_signature;

        // Check if user = signer has enough lamports to pay for storage rent
        require!(
            ctx.accounts.user.lamports() >= estimated_price,
            TaskError::InsufficientFunds
        );

        let cpi_accounts = system_program::Transfer {
            from: ctx.accounts.user.to_account_info(),
            to: gateway_state.to_account_info(),
        };

        let cpi_context =
            CpiContext::new(ctx.accounts.system_program.to_account_info(), cpi_accounts);

        system_program::transfer(cpi_context, estimated_price)?;

        //Hash the payload
        let generated_payload_hash =
            solana_program::keccak::hashv(&[&execution_info.payload]).to_bytes();

        // Persist the task
        let task = Task {
            payload_hash: generated_payload_hash,
            completed: false,
        }; 

        // Calculate the array index
        let index = (gateway_state.task_id % MAX_TASKS) as usize;

        let task_state = &mut ctx.accounts.task_state.load_mut()?;
        
        write_task_to_task_state(task_state, task, index)?;

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

        ctx.accounts.gateway_state.task_id += 1;

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

        // Check if the task_id for the callback is still available
        require!(MAX_TASKS + task_id > gateway_state.task_id, TaskError::TaskIdAlreadyPruned);

        let index = (task_id % MAX_TASKS) as usize;
        
        let task_state = &mut ctx.accounts.task_state.load_mut()?;
        
        let mut task = get_task_from_task_state(task_state, index)?;

        // Check if the task is already completed
        require!(!task.completed, TaskError::TaskAlreadyCompleted);

        // Concatenate packet data elements,
        // use saved in contract payload_hash to verify that the payload hash wasn't manipulated

        let mut data = Vec::new();
        data.extend_from_slice(source_network.as_bytes());
        data.extend_from_slice(CHAIN_ID.as_bytes());
        data.extend_from_slice(task_id.to_string().as_bytes());
        data.extend_from_slice(task.payload_hash.as_slice());
        data.extend_from_slice(post_execution_info.result.as_slice());
        data.extend_from_slice(post_execution_info.callback_address.as_slice());
        data.extend_from_slice(post_execution_info.callback_selector.as_slice());

        let packet_hash =
            solana_program::hash::hashv(&[&solana_program::keccak::hashv(&[&data]).to_bytes()]);

        // Packet hash verification
        require!(
            packet_hash.to_bytes() == post_execution_info.packet_hash,
            TaskError::InvalidPacketHash
        );

        // Decode the hex secret gateway public key
        let expected_pubkey_bytes =
            &decode(&SECRET_GATEWAY_PUBKEY[2..]).map_err(|_| TaskError::InvalidPublicKey)?[1..];

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
            recovered_pubkey.to_bytes() == expected_pubkey_bytes,
            TaskError::InvalidPacketSignature
        );

        // Mark the task as completed
        task.completed = true;

        write_task_to_task_state(task_state, task, index)?;

        let callback_data = CallbackData {
            task_id: task_id,
            result: post_execution_info.result,
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
        require!(
            post_execution_info.callback_address.len() % 32 == 0,
            TaskError::InvalidCallbackAddresses
        );

        let mut callback_account_metas = Vec::new();
        let mut callback_account_infos = Vec::new();

        // Add the PDA as the signer
        // Modify the AccountInfo to set is_writable to false for gateway_state
        let mut gateway_state_account_info = ctx.accounts.gateway_state.to_account_info().clone();
        gateway_state_account_info.is_writable = false;
        gateway_state_account_info.is_signer = true;
        callback_account_metas.push(AccountMeta::new_readonly(
            gateway_state_account_info.key(),
            true,
        ));
        callback_account_infos.push(gateway_state_account_info);

        // Add the system_program account
        callback_account_metas.push(AccountMeta::new_readonly(
            ctx.accounts.system_program.key(),
            false,
        ));
        callback_account_infos.push(ctx.accounts.system_program.to_account_info());

        let mut found_addresses = std::collections::HashSet::new();
        let mut remaining_accounts_iter = ctx.remaining_accounts.iter();

        for chunk in post_execution_info.callback_address.chunks(32) {
            match Pubkey::try_from(chunk) {
                Ok(pubkey) => {
                    if pubkey == ctx.accounts.gateway_state.key() || pubkey == *ctx.program_id {
                        continue;
                    }

                    if let Some(account) =
                        remaining_accounts_iter.find(|account| account.key == &pubkey)
                    {
                        if found_addresses.insert(pubkey) {
                            callback_account_infos.push(account.clone());
                            callback_account_metas
                                .push(AccountMeta::new(*account.key, account.is_signer));
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
            &callback_account_infos,
            &[&[GATEWAY_SEED.as_ref(), &[ctx.accounts.gateway_state.bump]]],
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
        const SECRET_PATH_ADDRESS: &str = "93FWvrFPNWzDQAAdbEQDW5P1pE7WuZc4HAdT6fdFPw26";
        let secretpath_address_pubkey = Pubkey::from_str(SECRET_PATH_ADDRESS).unwrap();

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

fn write_task_to_task_state(
    task_state: &mut RefMut<'_, TaskState>,
    task: Task,
    index: usize
) -> Result<()> {
    if index >= (MAX_TASKS as usize) {
        Err(TaskError::InvalidIndex.into())
    } else {
        let start = index * 33;
        task_state.tasks[start..(start + 32)].copy_from_slice(&task.payload_hash);
        task_state.tasks[start + 32] = task.completed as u8;
        Ok(())
    }
}

fn get_task_from_task_state(
    task_state: &mut RefMut<'_, TaskState>,
    index: usize
) -> Result<Task> {
    if index >= (MAX_TASKS as usize) {
        Err(TaskError::InvalidIndex.into())
    } else {
        let start = index * 33;
        let payload_hash: [u8; 32] = task_state.tasks[start..(start + 32)]
            .try_into()
            .map_err(|_| TaskError::InvalidPayloadHash)?;
        let completed: bool = task_state.tasks[start + 33] != 0;
        Ok(Task {
            payload_hash: payload_hash,
            completed: completed
        })
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
        space = 10240,
        seeds = [GATEWAY_SEED],
        bump
    )]
    pub gateway_state: Account<'info, GatewayState>,
    #[account(
        init,
        payer = owner,
        space = 10240,
        seeds = [TASK_SEED],
        bump
    )]
    pub task_state: AccountLoader<'info, TaskState>,
    #[account(mut, signer)]
    pub owner: Signer<'info>,
    #[account(address = system_program::ID)]
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(len: u64)]
pub struct IncreaseTaskState<'info> {
    #[account(
        mut, 
        seeds = [GATEWAY_SEED], 
        bump = gateway_state.bump, 
        has_one = owner
    )]
    pub gateway_state: Account<'info, GatewayState>,
    #[account(
        mut,
        realloc = len as usize,
        realloc::zero = true, 
        realloc::payer = owner,
        seeds = [TASK_SEED],
        bump
    )]
    pub task_state: AccountLoader<'info, TaskState>,
    #[account(mut, signer)]
    pub owner: Signer<'info>,
    #[account(address = system_program::ID)]
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct IncreaseTaskId<'info> {
    #[account(
        mut, 
        seeds = [GATEWAY_SEED], 
        bump = gateway_state.bump, 
        has_one = owner
    )]
    pub gateway_state: Account<'info, GatewayState>,
    #[account(mut, signer)]
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct PayoutBalance<'info> {
    #[account(
        mut, 
        seeds = [GATEWAY_SEED], 
        bump = gateway_state.bump, 
        has_one = owner
    )]
    pub gateway_state: Account<'info, GatewayState>,
    #[account(mut, signer)]
    pub owner: Signer<'info>,
    #[account(address = system_program::ID)]
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Send<'info> {
    #[account(
        mut, 
        seeds = [GATEWAY_SEED], 
        bump = gateway_state.bump
    )]
    pub gateway_state: Account<'info, GatewayState>,
    #[account(
        mut, 
        seeds = [TASK_SEED], 
        bump
    )]
    pub task_state: AccountLoader<'info, TaskState>,
    #[account(mut, signer)]
    pub user: Signer<'info>,
    #[account(address = system_program::ID)]
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct PostExecution<'info> {
    #[account(
        mut, 
        seeds = [GATEWAY_SEED], 
        bump = gateway_state.bump
    )]
    pub gateway_state: Account<'info, GatewayState>,
    #[account(
        mut, 
        seeds = [TASK_SEED], 
        bump
    )]
    pub task_state: AccountLoader<'info, TaskState>,
    #[account(mut, signer)]
    pub signer: Signer<'info>,
    #[account(address = system_program::ID)]
    pub system_program: Program<'info, System>,
}

#[account]
pub struct GatewayState {
    pub owner: Pubkey,
    pub task_id: u64,
    pub bump: u8,
}

#[account(zero_copy(unsafe))]
#[repr(C)]
pub struct TaskState {
    pub tasks: [u8; (33*MAX_TASKS + 1) as usize],
    //pub tasks: [u8; 1000 as usize],
}

#[derive(Clone, Copy, Default)]
pub struct Task {
    pub payload_hash: [u8; 32],
    pub completed: bool,
}

#[derive(Clone, AnchorSerialize, AnchorDeserialize)]
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

#[derive(Clone, AnchorSerialize, AnchorDeserialize)]
pub struct PostExecutionInfo {
    pub packet_hash: [u8; 32],
    pub callback_address: Vec<u8>,
    pub callback_selector: Vec<u8>,
    pub callback_gas_limit: Vec<u8>,
    pub packet_signature: [u8; 65],
    pub result: Vec<u8>,
}

#[derive(Clone, AnchorSerialize, AnchorDeserialize)]
pub struct CallbackData {
    task_id: u64,
    result: Vec<u8>,
}

#[derive(Clone, AnchorSerialize, AnchorDeserialize)]
pub struct SendResponse {
    pub request_id: u64,
}

#[derive(Clone, AnchorSerialize, AnchorDeserialize)]
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
