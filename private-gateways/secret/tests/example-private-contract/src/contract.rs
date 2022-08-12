use cosmwasm_std::{
    to_binary, Api, Binary, Env, Extern, HandleResponse, HandleResult, InitResponse, InitResult,
    Querier, QueryResult, StdError, Storage,
};
use secret_toolkit::utils::{pad_handle_result, pad_query_result, HandleCallback};

use crate::{
    msg::{CountResponse, GatewayMsg, HandleMsg, InitMsg, QueryMsg},
    state::{config, config_read, State},
};
use tnls::msg::{InputResponse, PostExecutionMsg, PrivContractHandleMsg, ResponseStatus::Success};

use serde::{Deserialize, Serialize};

/// pad handle responses and log attributes to blocks of 256 bytes to prevent leaking info based on
/// response size
pub const BLOCK_SIZE: usize = 256;

pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: Env,
    msg: InitMsg,
) -> InitResult {
    let state = State {
        gateway_address: msg.gateway_address,
        gateway_hash: msg.gateway_hash,
        gateway_key: msg.gateway_key,
        count: 0,
    };
    config(&mut deps.storage).save(&state)?;

    Ok(InitResponse::default())
}

pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> HandleResult {
    let response = match msg {
        HandleMsg::Input { message } => _handle(deps, env, message),
    };
    pad_handle_result(response, BLOCK_SIZE)
}

// acts like a gateway message handle filter
fn _handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: PrivContractHandleMsg,
) -> HandleResult {
    // verify signature with stored gateway public key
    let gateway_key = config_read(&deps.storage).load()?.gateway_key;
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
        "add_one" => try_add_one(deps, env, msg.input_values, msg.task_id, msg.input_hash),
        _ => Err(StdError::generic_err("invalid handle".to_string())),
    }
}

#[derive(Deserialize, Default)]
struct AddOneInputs {
    pub my_value: u8,
}

#[derive(Serialize)]
struct AddOneResults {
    pub my_value: u8,
}

fn try_add_one<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: Env,
    input_values: String,
    task_id: u64,
    input_hash: Binary,
) -> HandleResult {
    // increment count each time this handle is called
    config(&mut deps.storage).update(|mut state| {
        state.count += 1;
        Ok(state)
    })?;

    let input: AddOneInputs = serde_json_wasm::from_str(&input_values)
        .map_err(|err| StdError::generic_err(err.to_string()))?;

    let result = serde_json_wasm::to_string(&AddOneResults {
        my_value: input.my_value + 1,
    })
    .unwrap();

    let config = config_read(&deps.storage).load()?;

    let callback_msg = GatewayMsg::Output {
        outputs: PostExecutionMsg {
            result,
            task_id,
            input_hash,
        },
    }
    .to_cosmos_msg(config.gateway_hash, config.gateway_address, None)?;

    Ok(HandleResponse {
        messages: vec![callback_msg],
        log: vec![],
        data: Some(to_binary(&InputResponse { status: Success })?),
    })
}

pub fn query<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>, msg: QueryMsg) -> QueryResult {
    let response = match msg {
        QueryMsg::GetCount {} => query_count(deps),
    };
    pad_query_result(response, BLOCK_SIZE)
}

fn query_count<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>) -> QueryResult {
    let state = config_read(&deps.storage).load()?;
    to_binary(&CountResponse { count: state.count })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use cosmwasm_std::{coins, from_binary, HumanAddr, StdError};

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env("creator", &coins(1000, "earth"));
        let msg = InitMsg {
            gateway_address: HumanAddr("fake address".to_string()),
            gateway_hash: "fake code hash".to_string(),
            gateway_key: Binary(b"fake key".to_vec()),
        };

        // we can just call .unwrap() to assert this was a success
        let res = init(&mut deps, env, msg).unwrap();
        assert_eq!(0, res.messages.len());

        // it worked, let's query
        let res = query(&deps, QueryMsg::GetCount {});
        assert!(res.is_ok(), "query failed: {}", res.err().unwrap());
        let value: CountResponse = from_binary(&res.unwrap()).unwrap();
        assert_eq!(0, value.count);
    }

    #[test]
    fn test_handle() {
        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env("creator", &coins(1000, "earth"));
        let init_msg = InitMsg {
            gateway_address: HumanAddr("fake address".to_string()),
            gateway_hash: "fake code hash".to_string(),
            gateway_key: Binary(b"fake key".to_vec()),
        };
        init(&mut deps, env.clone(), init_msg).unwrap();

        // test invalid handle
        let handle_msg = HandleMsg::Input {
            message: PrivContractHandleMsg {
                input_values: "{\"my_value\": 1}".to_string(),
                handle: "add_two".to_string(),
                task_id: 1,
                input_hash: Binary(vec![0; 32]),
                signature: Binary(vec![0; 64]),
            },
        };
        let err = handle(&mut deps, env.clone(), handle_msg).unwrap_err();
        assert_eq!(err, StdError::generic_err("invalid handle".to_string()));

        let handle_msg = HandleMsg::Input {
            message: PrivContractHandleMsg {
                input_values: "{\"my_value\": 1}".to_string(),
                handle: "add_one".to_string(),
                task_id: 1,
                input_hash: Binary(vec![0; 32]),
                signature: Binary(vec![0; 64]),
            },
        };
        let handle_result = handle(&mut deps, env.clone(), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle failed: {}",
            handle_result.err().unwrap()
        );
        let handle_answer: InputResponse =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        assert_eq!(handle_answer.status, Success);
    }
}
