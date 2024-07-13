use anchor_lang::prelude::*;

#[error_code]
pub enum TaskError {
    #[msg("Task already completed")]
    TaskAlreadyCompleted,
    #[msg("Invalid payload hash")]
    InvalidPayloadHash,
    #[msg("Invalid payload hash size (must be 32 bytes long)")]
    InvalidPayloadHashSize,
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
    #[msg("Task Id already pruned")]
    TaskIdAlreadyPruned,
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
    #[msg("Gateway state is not a PDA")]
    InvalidGatewayState,
    #[msg("PDA is already initialized")]
    PDAAlreadyInitialized,
    #[msg("Only owner can call this function!")]
    NotOwner
}