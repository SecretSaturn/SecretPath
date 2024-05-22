use anchor_lang::prelude::*;

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
    #[msg("Invalid lookup index")]
    InvalidIndex,
    #[msg("Task Id already pruned")]
    TaskIdAlreadyPruned,
}

#[error_code]
pub enum GatewayError {
    #[msg("The new task_id must be greater than the current task_id")]
    TaskIdTooLow,
}