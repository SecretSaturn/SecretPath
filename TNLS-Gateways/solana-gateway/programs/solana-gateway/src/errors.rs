use anchor_lang::prelude::*;

#[error_code]
pub enum TaskError {
    #[msg("Task already completed")]
    TaskAlreadyCompleted,
    #[msg("Invalid payload hash")]
    InvalidPayloadHash,
    #[msg("Invalid packet hash")]
    InvalidPacketHash,
    #[msg("Invalid Public key")]
    InvalidPublicKey,
    #[msg("Secp256k1 recovery failed")]
    Secp256k1RecoverFailure,
    #[msg("Invalid packet signature")]
    InvalidPacketSignature,
    #[msg("Task not found")]
    TaskNotFound,
    #[msg("Insufficient funds")]
    InsufficientFunds,
    #[msg("Invalid lookup index")]
    InvalidIndex,
    #[msg("Invalid TaskID")]
    InvalidTaskId,
    #[msg("Callback Addresses are invalid")]
    InvalidCallbackAddresses,
    #[msg("Borsh Data Serialization failed")]
    BorshDataSerializationFailed,
    #[msg("Invalid Callback Selector")]
    InvalidCallbackSelector,
    #[msg("MissingRequiredSignature")]
    MissingRequiredSignature
}

#[error_code]
pub enum GatewayError {
    #[msg("The new task_id must be greater than the current task_id")]
    TaskIdTooLow,
    #[msg("Only owner can call this function!")]
    NotOwner
}

#[error_code]
pub enum ProgramError {
    #[msg("The signer is not the Secretpath Gateway program")]
    InvalidSecretPathGateway
}