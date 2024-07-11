use cosmwasm_std::{
    entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError,
    StdResult, to_vec, ContractResult, SystemResult
};
use anybuf::Anybuf;
use secret_toolkit::{
    crypto::{sha_256},
    utils::{pad_handle_result, pad_query_result, HandleCallback},
};
use crate::{
    msg::{ExecuteMsg, GatewayMsg, InstantiateMsg, QueryMsg, MigrateMsg},
    state::{State, Input, CONFIG},
};
use tnls::{
    msg::{PostExecutionMsg, PrivContractHandleMsg},
    state::Task
};
use base64::{engine::general_purpose, Engine};

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
        ExecuteMsg::Input { message } => try_handle(deps, env, info, message)
    };
    pad_handle_result(response, BLOCK_SIZE)
}

#[entry_point]
pub fn migrate(_deps: DepsMut, _env: Env, msg: MigrateMsg) -> StdResult<Response> {
    match msg {
        MigrateMsg::Migrate {} => {
            Ok(Response::default())
        }
    }
}


// acts like a gateway message handle filter
fn try_handle(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: PrivContractHandleMsg,
) -> StdResult<Response> {
   // verify signature with stored gateway public key
    
   let config = CONFIG.load(deps.storage)?;

   if info.sender != config.gateway_address {
       return Err(StdError::generic_err("Only SecretPath Gateway can call this function"));
   }

   deps.api.secp256k1_verify(
           msg.input_hash.as_slice(),
           msg.signature.as_slice(),
           config.gateway_key.as_slice(),
       )
       .map_err(|err| StdError::generic_err(err.to_string()))?;

   // combine input values and task to create verification hash, once with the unsafe_payload flag = true and once = falsecargo 
   let input_hash_safe = sha_256(&[msg.input_values.as_bytes(), msg.task.task_id.as_bytes(),&[0u8]].concat());
   let input_hash_unsafe = sha_256(&[msg.input_values.as_bytes(), msg.task.task_id.as_bytes(),&[1u8]].concat());

   if msg.input_hash.as_slice() != input_hash_safe.as_slice() {
       if msg.input_hash.as_slice() == input_hash_unsafe.as_slice() {
           return Err(StdError::generic_err("Payload was marked as unsafe, not executing"));
       }
       return Err(StdError::generic_err("Safe input hash does not match provided input hash"));
   }
    // determine which function to call based on the included handle
    let handle = msg.handle.as_str();
    match handle {
        "request_random" => {
            try_random(deps, env, msg.input_values, msg.task, msg.input_hash)
        }
        _ => Err(StdError::generic_err("invalid handle".to_string())),
    }
}

fn try_random(
    deps: DepsMut,
    env: Env,
    input_values: String,
    task: Task,
    input_hash: Binary,
) -> StdResult<Response> {
    let config = CONFIG.load(deps.storage)?;

    let input: Input = serde_json_wasm::from_str(&input_values)
    .map_err(|err| StdError::generic_err(err.to_string()))?;

    let num_words = input.numWords;

    let base_random = match env.block.random {
        Some(random_value) => random_value,
        None => return Err(StdError::generic_err("No random value available")),
    };

    let mut random_numbers = Vec::new();

    for i in 0..num_words {
        let mut data = base_random.0.clone();
        data.extend_from_slice(&(i as u64).to_be_bytes());
        let hashed_number = sha_256(&data); 
        random_numbers.extend_from_slice(hashed_number.as_slice()); 
    }
    
    let result = general_purpose::STANDARD.encode(random_numbers);

    let gateway_code_hash = get_contract_code_hash(deps, config.gateway_address.to_string())?;

    let callback_msg = GatewayMsg::Output {
        outputs: PostExecutionMsg {
            result,
            task,
            input_hash,
        },
    }
    .to_cosmos_msg(
        gateway_code_hash,
        config.gateway_address.to_string(),
        None,
    )?;

    Ok(Response::new()
        .add_message(callback_msg)
        .add_attribute("status", "provided RNG complete"))
}

fn get_contract_code_hash(deps: DepsMut, contract_address: String) -> StdResult<String> {
    let code_hash_query: cosmwasm_std::QueryRequest<cosmwasm_std::Empty> = cosmwasm_std::QueryRequest::Stargate {
        path: "/secret.compute.v1beta1.Query/CodeHashByContractAddress".into(),
        data: Binary(Anybuf::new()
        .append_string(1, contract_address)
        .into_vec())
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
        SystemResult::Ok(ContractResult::Ok(value)) => Ok(value)
    }?;

    // Remove the "\n@" if it exists at the start of the code_hash
    let mut code_hash_str = String::from_utf8(code_hash.to_vec()).map_err(|err| {
        StdError::generic_err(format!("Invalid UTF-8 sequence: {}", err))
    })?;

    if code_hash_str.starts_with("\n@") {
        code_hash_str = code_hash_str.trim_start_matches("\n@").to_string();
    }

    Ok(code_hash_str)
}

#[entry_point]
pub fn query(_deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    let response = match msg {
        QueryMsg::Query {} => to_binary("")
    };
    pad_query_result(response, BLOCK_SIZE)
}


#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{from_binary, Addr};

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info("sender", &[]);
        let msg = InstantiateMsg {
            gateway_address: Addr::unchecked("fake address".to_string()),
            gateway_hash: "fake code hash".to_string(),
            gateway_key: Binary(b"fake key".to_vec()),
        };

        // we can just call .unwrap() to assert this was a success
        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
        assert_eq!(0, res.messages.len());

        // it worked, let's query
        let res = query(deps.as_ref(), env.clone(), QueryMsg::Query {});
        assert!(res.is_ok(), "query failed: {}", res.err().unwrap());
        let value: QueryResponse = from_binary(&res.unwrap()).unwrap();
        assert_eq!("placeholder", value.message);
    }

    #[test]
    fn request_score() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info("sender", &[]);
        let init_msg = InstantiateMsg {
            gateway_address: Addr::unchecked("fake address".to_string()),
            gateway_hash: "fake code hash".to_string(),
            gateway_key: Binary(b"fake key".to_vec()),
        };
        instantiate(deps.as_mut(), env.clone(), info.clone(), init_msg).unwrap();

        let message = PrivContractHandleMsg {
            input_values: "{\"address\":\"0x249C8753A9CB2a47d97A11D94b2179023B7aBCca\",\"name\":\"bob\",\"offchain_assets\":100,\"onchain_assets\":100,\"liabilities\":100,\"missed_payments\":100,\"income\":100}".to_string(),
            handle: "request_score".to_string(),
            user_address: Addr::unchecked("0x1".to_string()),
            task_id: 1,
            input_hash: to_binary(&"".to_string()).unwrap(),
            signature: to_binary(&"".to_string()).unwrap(),
        };
        let handle_msg = ExecuteMsg::Input { message };

        let handle_response =
            execute(deps.as_mut(), env.clone(), info.clone(), handle_msg).unwrap();
        let result = &handle_response.attributes[0].value;
        assert_eq!(result, "private computation complete");
    }
}
