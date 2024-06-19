use anchor_lang::{
        prelude::*,
        system_program::{transfer, Transfer},
        solana_program::{
            sysvar::{rent::Rent, Sysvar}
        }
};
use solana_program::{
    program::invoke,
    instruction::Instruction,
    secp256k1_recover::{secp256k1_recover, Secp256k1Pubkey}
};
use base64::{
    engine::general_purpose::STANDARD,
    Engine
};

pub mod errors;
use crate::errors::{TaskError, GatewayError};

declare_id!("3KU2e3f5sHiZ7KnxJvRgeHAaVHuw8fJLiyGQmonGy4YZ");

// Constants
const TASK_DESTINATION_NETWORK: &str = "pulsar-3";
const SECRET_GATEWAY_PUBKEY: &str = "BG0KrD7xDmkFXpNMqJn1CLpRaDLcdKpO1NdBBS7VpWh3TZnTv+1kGnk1rnOqyONJONt0fC8OiyqpXCXQaaV1zIs=";

#[program]
mod solana_gateway {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let gateway_state = &mut ctx.accounts.gateway_state;
        gateway_state.owner = *ctx.accounts.user.key;
        gateway_state.task_id = 0;
        gateway_state.tasks = Vec::new();

        Ok(())
    }

    pub fn increase_task_id(ctx: Context<IncreaseTaskId>, new_task_id: u64) -> Result<()> {
        let gateway_state = &mut ctx.accounts.gateway_state;
        if new_task_id <= gateway_state.task_id {
            return Err(GatewayError::TaskIdTooLow.into());
        }
        gateway_state.task_id = new_task_id;
        Ok(())
    }

    pub fn send(
        ctx: Context<Send>,
        payload_hash: [u8; 32],
        user_address: Pubkey,
        routing_info: String,
        execution_info: ExecutionInfo,
    ) -> Result<SendResponse> {
        let gateway_state = &mut ctx.accounts.gateway_state;

        // Fetch the current lamports per signature cost for the singature 
        let lamports_per_signature = 10;

        //Calculate the rent for extra storage
        let lamports_per_byte_year = Rent::get().unwrap().lamports_per_byte_year;
        
        // Estimate the cost based on the callback gas limit
        let estimated_price = execution_info.callback_gas_limit as u64 * lamports_per_signature 
        + 33*2*lamports_per_byte_year;
                
        let lamports_sent = ctx.accounts.user.lamports();

        //Check if enough lamports were sent to cover the callback + the extra storage costs
        require!(
            lamports_sent >= estimated_price,
            TaskError::InsufficientFunds
        );

        // Refund any excess lamports paid beyond the estimated price
        if lamports_sent > estimated_price {
            let refund_amount = lamports_sent - estimated_price;
            
            let cpi_accounts = Transfer {
                from: ctx.accounts.user.to_account_info(),
                to: ctx.accounts.user.to_account_info(),
            };
        
            let cpi_context = CpiContext::new(ctx.accounts.system_program.to_account_info(), cpi_accounts);
        
            transfer(cpi_context, refund_amount)?;
        }

        //Hash the payload
        let generated_payload_hash = solana_program::keccak::hash(&["\x19Ethereum Signed Message:\n32".as_bytes(),&solana_program::keccak::hash(&execution_info.payload).to_bytes()].concat());

/*      // Payload hash verification
        require!(
            generated_payload_hash.to_bytes() == payload_hash,
            TaskError::InvalidPayloadHash
        ); */

        // Persist the task
        let task = Task {
            payload_hash: payload_hash,
            task_id: gateway_state.task_id,
            completed: false
        };

        // Calculate the array index
        let index = (gateway_state.task_id % gateway_state.max_tasks) as usize;

         // Reallocate account space if necessary
         if index >= gateway_state.tasks.len() {
             let current_len = gateway_state.tasks.len();
             if current_len >= gateway_state.max_tasks as usize {
                 let new_max_tasks = gateway_state.max_tasks + 10;
                 let new_space = 8 + 8 + 8 + (std::mem::size_of::<Task>() * new_max_tasks as usize);
                 gateway_state.to_account_info().realloc(new_space, false)?;
                 gateway_state.max_tasks = new_max_tasks;
             }
 
             // If the array isn't filled up yet, just push it to the end 
             gateway_state.tasks.push(task);
         } else {
             // If a task already exists, it will be overwritten as expected from the max.
             gateway_state.tasks[index] = task;
         }

        let task_id = gateway_state.task_id;

        emit!(LogNewTask {
            task_id: task_id,
            task_destination_network: TASK_DESTINATION_NETWORK.to_string(),
            user_address: user_address,
            routing_info: routing_info,
            payload_hash: payload_hash,
            execution_info: execution_info,
        });

        gateway_state.task_id += 1;

        Ok(SendResponse { request_id: task_id })
    }

    pub fn post_execution(
        ctx: Context<PostExecution>,
        task_id: u64,
        source_network: String,
        post_execution_info: PostExecutionInfo,
    ) -> Result<()> {
        let gateway_state = &mut ctx.accounts.gateway_state;
        
        let index = (task_id % gateway_state.max_tasks) as usize;

        require!(index < gateway_state.tasks.len(), TaskError::InvalidIndex);

        let task = gateway_state.tasks[index];

        require!(task_id == task.task_id, TaskError::TaskIdAlreadyPruned);

        // Check if the task is already completed
        require!(!task.completed, TaskError::TaskAlreadyCompleted);

        // Check if the payload hashes match
        require!(
            task.payload_hash == post_execution_info.payload_hash,
            TaskError::InvalidPayloadHash
        );

        // Concatenate packet data elements
        let data = [
            source_network.as_bytes(),
            TASK_DESTINATION_NETWORK.as_bytes(),
            &task_id.to_le_bytes(),
            &post_execution_info.payload_hash,
            &post_execution_info.result,
            &post_execution_info.callback_address.as_bytes(),
            &post_execution_info.callback_selector.as_bytes(),
        ].concat();

        // Perform Keccak256 + sha256 hash
        let packet_hash = solana_program::keccak::hash(&solana_program::hash::hash(&data).to_bytes());

        // Packet hash verification
        require!(
            packet_hash.to_bytes() == post_execution_info.packet_hash,
            TaskError::InvalidPacketHash
        );

        // Decode the base64 public key
        let pubkey_bytes = STANDARD.decode(SECRET_GATEWAY_PUBKEY).unwrap();
        let expected_pubkey = Secp256k1Pubkey(pubkey_bytes.try_into().unwrap());

        // Extract the recovery ID and signature from the packet signature
        // RecoveryID here might me 27,28 due to the ethereum bug
        let recovery_id = post_execution_info.packet_signature[64];
        let signature = &post_execution_info.packet_signature[..64];

        // Perform the signature recovery
        let recovered_pubkey = secp256k1_recover(&packet_hash.to_bytes(), recovery_id, signature)
            .map_err(|_| error!(TaskError::InvalidPacketSignature))?;

        // Verify that the recovered public key matches the expected public key
        require!(
            recovered_pubkey == expected_pubkey,
            TaskError::InvalidPacketSignature
        );

        // Mark the task as completed
        gateway_state.tasks[index].completed = true;

        let callback_data = CallbackData {
            callback_selector: post_execution_info.callback_selector.clone(),
            task_id: task_id,
            result: post_execution_info.result,
        };

        let borsh_data = callback_data.try_to_vec().unwrap();

        // Convert the String to a Pubkey
        let callback_address_pubkey = Pubkey::try_from(post_execution_info.callback_address.as_str())
        .expect("Invalid Pubkey for callback address");
        let callback_selector_pubkey = Pubkey::try_from(post_execution_info.callback_selector.as_str())
        .expect("Invalid Pubkey for callback selector");
       
        // Execute the callback
        let callback_result = invoke(
            &Instruction {
                program_id: callback_selector_pubkey,
                accounts: vec![AccountMeta::new(callback_address_pubkey, false)],
                data: borsh_data,
            },
            &[],
        );

        emit!(TaskCompleted {
            task_id,
            callback_successful: callback_result.is_ok()
        });

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = user, space = 8 + 8 + 8 + 9000)]
    pub gateway_state: Account<'info, GatewayState>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct IncreaseTaskId<'info> {
    #[account(mut, has_one = owner)]
    pub gateway_state: Account<'info, GatewayState>,
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct Send<'info> {
    #[account(mut)]
    pub gateway_state: Account<'info, GatewayState>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct PostExecution<'info> {
    #[account(mut)]
    pub gateway_state: Account<'info, GatewayState>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct GatewayState {
    pub owner: Pubkey,
    pub task_id: u64,
    pub tasks: Vec<Task>,
    pub max_tasks: u64, 
}

#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize, Copy)]
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
    pub nonce: [u8; 12],
    pub callback_gas_limit: u32,
    pub payload: Vec<u8>,
    pub payload_signature: Vec<u8>,
}

#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct PostExecutionInfo {
    pub payload_hash: [u8; 32],
    pub packet_hash: [u8; 32],
    pub callback_address: String,
    pub callback_selector: String,
    pub callback_gas_limit: u32,
    pub packet_signature: Vec<u8>,
    pub result: Vec<u8>,
}

#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct CallbackData {
    callback_selector: String,
    task_id: u64,
    result: Vec<u8>,
}

#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct SendResponse {
    pub request_id: u64,
}

#[event]
pub struct TaskCompleted {
    pub task_id: u64,
    pub callback_successful: bool,
}

#[event]
pub struct LogNewTask {
    pub task_id: u64,
    pub task_destination_network: String,
    pub user_address: Pubkey,
    pub routing_info: String,
    pub payload_hash: [u8; 32],
    pub execution_info: ExecutionInfo,
}