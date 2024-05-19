use anchor_lang::prelude::*;
use anchor_lang::system_program::{transfer, Transfer, create_account, CreateAccount};
use anchor_lang::solana_program::{sysvar::fees::Fees, sysvar::rent::Rent ,sysvar::Sysvar};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use solana_program::hash::hashv;
use solana_program::keccak::Hasher;
use solana_program::program::invoke;
use solana_program::instruction::Instruction;
use solana_program::secp256k1_recover::{secp256k1_recover, Secp256k1Pubkey};

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
        gateway_state.length = 0;
        gateway_state.page_count = 0;
        Ok(())
    }

    pub fn increase_task_id(ctx: Context<IncreaseTaskId>, new_task_id: u64) -> Result<()> {
        let gateway_state = &mut ctx.accounts.gateway_state;
        if new_task_id <= gateway_state.task_id {
            return Err(GatewayError::InvalidTaskId.into());
        }
        gateway_state.task_id = new_task_id;
        Ok(())
    }

    pub fn send(
        ctx: Context<Send>,
        payload_hash: [u8; 32],
        user_address: Pubkey,
        _routing_info: String,
        execution_info: ExecutionInfo,
    ) -> Result<()> {
        let gateway_state = &mut ctx.accounts.gateway_state;

        // Fetch the current lamports per signature cost for the singature 
        let lamports_per_signature = Fees::get().unwrap().fee_calculator.lamports_per_signature;

        //Calculate the rent for extra storage
        let lamports_per_byte_year = Rent::get().unwrap().lamports_per_byte_year;
        
        // Estimate the cost based on the callback gas limit
        let estimated_price = execution_info.callback_gas_limit as u64 * lamports_per_signature + 33*2*lamports_per_byte_year;
                
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
        let mut hasher = Hasher::default();
        hasher.hash(&execution_info.payload);
        let generated_payload_hash = hasher.result();

        // Payload hash verification
        require!(
            generated_payload_hash.to_bytes() == payload_hash,
            TaskError::InvalidPayloadHash
        );

        // Persist the task
        let task = Task {
            payload_hash: payload_hash,
            completed: false,
        };

        // Determine the page index and element index within the page
        let page_index = gateway_state.length / ELEMENTS_PER_PAGE as u64;
        let element_index = (gateway_state.length % ELEMENTS_PER_PAGE as u64) as usize;


        // Check if a new page is needed
        if gateway_state.length % ELEMENTS_PER_PAGE as u64 == 0 {

            // Create a new page account
            let gateway_key = gateway_state.key();
            let page_index_bytes = page_index.to_le_bytes();

            let page_seeds = &[
                b"page",
                gateway_key.as_ref(),
                &page_index_bytes,
            ];

            let page_signer = &[&page_seeds[..]];

            let space = 8 + 8 + std::mem::size_of::<Task>() * ELEMENTS_PER_PAGE;
            let lamports = Rent::get()?.minimum_balance(space);
            
            let cpi_accounts = CreateAccount {
                from: ctx.accounts.user.to_account_info(),
                to: ctx.accounts.page_account.to_account_info(),
            };

            let cpi_context = CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                cpi_accounts,
                page_signer,
            );

            create_account(cpi_context, lamports, space as u64, &id())?;
            gateway_state.page_count += 1;
        }

        let page_account = &mut ctx.accounts.page_account;
        page_account.elements[element_index] = task;
        page_account.count += 1;

        gateway_state.length += 1;

        emit!(LogNewTask {
            task_id: gateway_state.task_id,
            task_destination_network: TASK_DESTINATION_NETWORK.to_string(),
            user_address: user_address,
            payload_hash: payload_hash,
            execution_info: execution_info,
        });

        gateway_state.task_id += 1;
        Ok(())
    }

    pub fn post_execution(
        ctx: Context<PostExecution>,
        task_id: u64,
        _source_network: String,
        post_execution_info: PostExecutionInfo,
    ) -> Result<()> {
        let _gateway_state = &mut ctx.accounts.gateway_state;

        let _page_index = task_id / ELEMENTS_PER_PAGE as u64;
        let element_index = (task_id % ELEMENTS_PER_PAGE as u64) as usize;
    
        // Fetch the page account
        let page_account = &ctx.accounts.page_account;
    
        // Retrieve the task from the page
        let mut task = page_account
            .elements
            .get(element_index)
            .ok_or(TaskError::TaskNotFound)?
            .clone();

        // Check if the task is already completed
        require!(!task.completed, TaskError::TaskAlreadyCompleted);

        // Check if the payload hashes match
        require!(
            task.payload_hash == post_execution_info.payload_hash,
            TaskError::InvalidPayloadHash
        );

        // Concatenate packet data elements
        let data = [
            post_execution_info.source_network.as_bytes(),
            TASK_DESTINATION_NETWORK.as_bytes(),
            &task_id.to_le_bytes(),
            &post_execution_info.payload_hash,
            &post_execution_info.result,
            &post_execution_info.callback_address.as_bytes(),
            &post_execution_info.callback_selector.as_bytes(),
        ]
            .concat();

        // Perform Keccak256 + sha256 hash
        let packet_hash = hashv(&[hashv(&[&data]).to_bytes().as_ref()]);

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
        task.completed = true;

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
    #[account(init, payer = user, space = 8 + 8 + 8 + 100)]
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

const ELEMENTS_PER_PAGE: usize = 100; // Adjust based on the element size and 10,000 bytes limit

#[account]
pub struct Page {
    pub elements: [Task; ELEMENTS_PER_PAGE],
    pub count: u64, // Number of elements in the page
}

#[derive(Accounts)]
#[instruction(page_index: u64)]
pub struct Send<'info> {
    #[account(mut)]
    pub gateway_state: Account<'info, GatewayState>,
    #[account(
        init,
        payer = user, 
        space = 8 + 8 + std::mem::size_of::<Task>() * ELEMENTS_PER_PAGE, 
        seeds = [b"page", gateway_state.key().as_ref(), &page_index.to_le_bytes()], 
        bump
    )]
    pub page_account: Account<'info, Page>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(task_id: u64)]
pub struct PostExecution<'info> {
    #[account(mut)]
    pub gateway_state: Account<'info, GatewayState>,
    #[account(
        seeds = [b"page", gateway_state.key().as_ref(), &(task_id / ELEMENTS_PER_PAGE as u64).to_le_bytes()],
        bump
    )]
    pub page_account: Account<'info, Page>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct GatewayState {
    pub owner: Pubkey,
    pub task_id: u64,
    pub length: u64,
    pub page_count: u64,
}

#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct Task {
    pub payload_hash: [u8; 32],
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
    pub source_network: String,
    pub payload_hash: [u8; 32],
    pub packet_hash: [u8; 32],
    pub callback_address: String,
    pub callback_selector: String,
    pub callback_gas_limit: u32,
    pub packet_signature: Vec<u8>,
    pub result: Vec<u8>,
}

//#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct CallbackData {
    callback_selector: String,
    task_id: u64,
    result: Vec<u8>,
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
    pub payload_hash: [u8; 32],
    pub execution_info: ExecutionInfo,
}

#[error_code]
pub enum TaskError {
    #[msg("Task already completed")]
    TaskAlreadyCompleted,
    #[msg("Invalid payload hash")]
    InvalidPayloadHash,
    #[msg("Invalid packet hash")]
    InvalidPacketHash,
    #[msg("Invalid packet signature")]
    InvalidPacketSignature,
    #[msg("Task not found")]
    TaskNotFound,
    #[msg("Insufficient funds")]
    InsufficientFunds,
}

#[error_code]
pub enum GatewayError {
    #[msg("The new task_id must be greater than the current task_id.")]
    InvalidTaskId,
}
