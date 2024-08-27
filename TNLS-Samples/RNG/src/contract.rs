use crate::{
    msg::{ExecuteMsg, GatewayMsg, InstantiateMsg, MigrateMsg, QueryMsg},
    state::{Input, State, CONFIG},
};
use anybuf::Anybuf;
use base64::{engine::general_purpose, Engine};
use cosmwasm_std::{
    entry_point, to_binary, to_vec, Binary, ContractResult, Deps, DepsMut, Env, MessageInfo,
    Response, StdError, StdResult, SystemResult,
};
use secret_path::{
    msg::{PostExecutionMsg, PrivContractHandleMsg},
    state::Task,
};
use secret_toolkit::{
    crypto::{ContractPrng},
    utils::{pad_handle_result, pad_query_result, HandleCallback},
};
use rand_core::RngCore;

/// pad handle responses and log attributes to blocks of 256 bytes to prevent leaking info based on
/// response size
pub const BLOCK_SIZE: usize = 256;

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let state = State {
        gateway_address: msg.gateway_address,
        gateway_hash: msg.gateway_hash,
        gateway_key: msg.gateway_key,
    };

    CONFIG.save(deps.storage, &state)?;

    Ok(Response::default())
}

#[entry_point]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    let response = match msg {
        ExecuteMsg::Input { message } => try_handle(deps, env, info, message),
    };
    pad_handle_result(response, BLOCK_SIZE)
}

#[entry_point]
pub fn migrate(_deps: DepsMut, _env: Env, msg: MigrateMsg) -> StdResult<Response> {
    match msg {
        MigrateMsg::Migrate {} => Ok(Response::default()),
    }
}

// acts like a gateway message handle filter
fn try_handle(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    msg: PrivContractHandleMsg,
) -> StdResult<Response> {

    // determine which function to call based on the included handle
    let handle = msg.handle.as_str();
    match handle {
        "request_random" => try_random(deps, env, msg.input_values, msg.task, msg.input_hash),
        _ => Err(StdError::generic_err("invalid handle".to_string())),
    }
}

fn try_random(
    deps: DepsMut,  // Mutable dependencies
    env: Env,  // Contract environment
    input_values: String,  // Input values as string
    task: Task,  // Task-related data
    input_hash: Binary,  // Hash of the input data
) -> StdResult<Response> {
    // Load the contract configuration from storage
    let config = CONFIG.load(deps.storage)?;

    // Deserialize input values to an Input struct
    let input: Input = serde_json_wasm::from_str(&input_values)
        .map_err(|err| StdError::generic_err(err.to_string()))?;

    let num_words = input.numWords;  // Number of random words to generate

    // Initialize the PRNG (pseudo-random number generator) using the environment's block randomness
    let mut prng = ContractPrng::from_env(&env);

    // Create a buffer to store num_words * 32 bytes of random data
    let mut random_numbers = vec![0u8; (num_words * 32) as usize];

    // Fill the buffer with random bytes
    prng.fill_bytes(&mut random_numbers);

    // Encode the random numbers as a base64 string
    let result = general_purpose::STANDARD.encode(random_numbers);

    // Get the contract's code hash using the gateway address
    let gateway_code_hash = get_contract_code_hash(deps, config.gateway_address.to_string())?;

    // Create a callback message to send the result back through the gateway
    let callback_msg = GatewayMsg::Output {
        outputs: PostExecutionMsg {
            result,
            task,
            input_hash,
        },
    }
    .to_cosmos_msg(gateway_code_hash, config.gateway_address.to_string(), None)?;

    // Return the response with the callback message and status
    Ok(Response::new()
        .add_message(callback_msg)
        .add_attribute("status", "provided RNG complete"))
}

fn get_contract_code_hash(deps: DepsMut, contract_address: String) -> StdResult<String> {
    let code_hash_query: cosmwasm_std::QueryRequest<cosmwasm_std::Empty> =
        cosmwasm_std::QueryRequest::Stargate {
            path: "/secret.compute.v1beta1.Query/CodeHashByContractAddress".into(),
            data: Binary(Anybuf::new().append_string(1, contract_address).into_vec()),
        };

    let raw = to_vec(&code_hash_query).map_err(|serialize_err| {
        StdError::generic_err(format!("Serializing QueryRequest: {}", serialize_err))
    })?;

    let code_hash = match deps.querier.raw_query(&raw) {
        SystemResult::Err(system_err) => Err(StdError::generic_err(format!(
            "Querier system error: {}",
            system_err
        ))),
        SystemResult::Ok(ContractResult::Err(contract_err)) => Err(StdError::generic_err(format!(
            "Querier contract error: {}",
            contract_err
        ))),
        SystemResult::Ok(ContractResult::Ok(value)) => Ok(value),
    }?;

    // Remove the "\n@" if it exists at the start of the code_hash
    let mut code_hash_str = String::from_utf8(code_hash.to_vec())
        .map_err(|err| StdError::generic_err(format!("Invalid UTF-8 sequence: {}", err)))?;

    if code_hash_str.starts_with("\n@") {
        code_hash_str = code_hash_str.trim_start_matches("\n@").to_string();
    }

    Ok(code_hash_str)
}

#[entry_point]
pub fn query(_deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    let response = match msg {
        QueryMsg::Query {} => to_binary(""),
    };
    pad_query_result(response, BLOCK_SIZE)
}