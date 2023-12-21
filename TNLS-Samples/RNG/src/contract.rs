use cosmwasm_std::{
    entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError,
    StdResult,
};
use secret_toolkit::utils::{pad_handle_result, pad_query_result, HandleCallback};

use crate::{
    msg::{ExecuteMsg, GatewayMsg, InstantiateMsg, QueryMsg, QueryResponse},
    state::{State, CONFIG},
};
use tnls::msg::{PostExecutionMsg, PrivContractHandleMsg};

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

    // config(&mut deps.storage).save(&state)?;
    CONFIG.save(deps.storage, &state)?;

    Ok(Response::default())
}

#[entry_point]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    let response = match msg {
        ExecuteMsg::Input { message } => try_handle(deps, env, info, message),
        ExecuteMsg::ReturnRandom {} => return_random(deps, env, info),
    };
    pad_handle_result(response, BLOCK_SIZE)
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    let response = match msg {
        QueryMsg::Query {} => try_query(deps),
    };
    pad_query_result(response, BLOCK_SIZE)
}

// acts like a gateway message handle filter
fn try_handle(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    msg: PrivContractHandleMsg,
) -> StdResult<Response> {
    // verify signature with stored gateway public key
    let gateway_key = CONFIG.load(deps.storage)?.gateway_key;
    deps.api
        .secp256k1_verify(
            msg.input_hash.as_slice(),
            msg.signature.as_slice(),
            gateway_key.as_slice(),
        )
        .map_err(|err| StdError::generic_err(err.to_string()))?;

    // determine which function to call based on the included handle
    let handle = msg.handle.as_str();
    match handle {
        "request_random" => {
            try_random(deps, env, msg.input_values, msg.task_id, msg.input_hash)
        }
        _ => Err(StdError::generic_err("invalid handle".to_string())),
    }
}

fn return_random(
    _deps: DepsMut,
    env: Env,
    _info: MessageInfo,
) -> StdResult<Response> {

    let result = match env.block.random {
        Some(random_value) => random_value.to_base64(),
        None => return Err(StdError::generic_err("No random value available")),
    };

    Ok(Response::new().add_attribute("random", result))
}

fn try_random(
    deps: DepsMut,
    env: Env,
    _input_values: String,
    task_id: u64,
    input_hash: Binary,
) -> StdResult<Response> {
    let config = CONFIG.load(deps.storage)?;

    let result = match env.block.random {
        //Some(random_value) => format!("{{\"random\":{}}}", random_value.to_base64()),
        Some(random_value) => random_value.to_base64(),
        None => return Err(StdError::generic_err("No random value available")),
    };

    let callback_msg = GatewayMsg::Output {
        outputs: PostExecutionMsg {
            result,
            task_id,
            input_hash,
        },
    }
    .to_cosmos_msg(
        config.gateway_hash,
        config.gateway_address.to_string(),
        None,
    )?;

    Ok(Response::new()
        .add_message(callback_msg)
        .add_attribute("status", "provided RNG complete"))
}

fn try_query(_deps: Deps) -> StdResult<Binary> {
    let message = "placeholder".to_string();
    to_binary(&QueryResponse { message })
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
        assert_eq!(result, "private computation complete                                                                                                                                                                                                                                    ");
    }

    #[test]
    fn calculate_score() {
        let input = Input {
            address: "0x01".to_string(),
            name: Some("alice".to_string()),
            offchain_assets: 9,
            onchain_assets: 0,
            liabilities: 0,
            missed_payments: 0,
            income: 0,
        };
        let score = try_calculate_score(input).unwrap();
        assert_eq!(score, "{\"name\":\"alice\",\"result\":\"850\"}");

        let input = Input {
            address: "0x01".to_string(),
            name: Some("bob".to_string()),
            offchain_assets: 0,
            onchain_assets: 0,
            liabilities: 0,
            missed_payments: 0,
            income: 0,
        };
        let score = try_calculate_score(input).unwrap();
        assert_eq!(score, "{\"name\":\"bob\",\"result\":\"250\"}");

        let input = Input {
            address: "0x01".to_string(),
            name: None,
            offchain_assets: 0,
            onchain_assets: 1000000,
            liabilities: 499999,
            missed_payments: 0,
            income: 0,
        };
        let score = try_calculate_score(input).unwrap();
        assert_eq!(score, "{\"name\":\"0x01\",\"result\":\"450\"}");
    }
}
