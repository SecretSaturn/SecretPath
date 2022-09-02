use std::cmp::max;

use cosmwasm_std::{
    log, to_binary, Api, Binary, Env, Extern, HandleResponse, HandleResult, InitResponse,
    InitResult, Querier, QueryResult, StdError, Storage,
};
use secret_toolkit::utils::{pad_handle_result, pad_query_result, HandleCallback};

use crate::{
    msg::{GatewayMsg, HandleMsg, InitMsg, QueryMsg, QueryResponse, RicherResponse},
    state::{Input, Millionaire, State, CONFIG, MILLIONAIRES},
};
use tnls::msg::{InputResponse, PostExecutionMsg, PrivContractHandleMsg, ResponseStatus::Success};

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
    };

    // config(&mut deps.storage).save(&state)?;
    CONFIG.save(&mut deps.storage, &state)?;

    Ok(InitResponse::default())
}

pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> HandleResult {
    let response = match msg {
        HandleMsg::Input { message } => try_handle(deps, env, message),
    };
    pad_handle_result(response, BLOCK_SIZE)
}

pub fn query<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>, msg: QueryMsg) -> QueryResult {
    let response = match msg {
        QueryMsg::Query {} => query_input(deps),
    };
    pad_query_result(response, BLOCK_SIZE)
}

// acts like a gateway message handle filter
fn try_handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: PrivContractHandleMsg,
) -> HandleResult {
    // verify signature with stored gateway public key
    let gateway_key = CONFIG.load(&deps.storage)?.gateway_key;
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
        "submit_player" => {
            try_store_input(deps, env, msg.input_values, msg.task_id, msg.input_hash)
        }
        // "compare" => try_compare(deps, env, msg.input_values, msg.task_id, msg.input_hash),
        _ => Err(StdError::generic_err("invalid handle".to_string())),
    }
}

fn try_store_input<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: Env,
    input_values: String,
    task_id: u64,
    input_hash: Binary,
) -> HandleResult {
    let config = CONFIG.load(&deps.storage)?;

    let input: Input = serde_json_wasm::from_str(&input_values)
        .map_err(|err| StdError::generic_err(err.to_string()))?;

    let player = Millionaire::new(
        // if no name provided, use player address as name
        input.name.unwrap_or_else(|| input.address.clone()),
        input.worth,
        input.match_addr.clone(),
    );

    MILLIONAIRES.insert(&mut deps.storage, &input.address, player)?;

    let result: String = if MILLIONAIRES.contains(&deps.storage, &input.match_addr)
        && input.address
            == MILLIONAIRES
                .get(&deps.storage, &input.match_addr)
                .unwrap()
                .match_addr
    {
        let player1 = MILLIONAIRES.get(&deps.storage, &input.address).unwrap();
        let player2 = MILLIONAIRES.get(&deps.storage, &input.match_addr).unwrap();
        try_compare(player1, player2)
    } else {
        serde_json_wasm::to_string(&InputResponse { status: Success })
            .map_err(|err| StdError::generic_err(err.to_string()))?
    };

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
        log: vec![log("status", "private computation complete")],
        data: None,
    })
}

pub fn try_compare(player1: Millionaire, player2: Millionaire) -> String {
    let a = player1.name.clone();
    let b = player2.name.clone();

    let resp: RicherResponse = if player1 == player2 {
        RicherResponse {
            result: "It's a tie!".to_string(),
        }
    } else {
        let richer = max(player1, player2);
        RicherResponse {
            result: format!("The richer of {} and {} is {}", a, b, richer.name),
        }
    };

    serde_json_wasm::to_string(&resp).unwrap()
}

fn query_input<S: Storage, A: Api, Q: Querier>(_deps: &Extern<S, A, Q>) -> QueryResult {
    let message = "congratulations".to_string();
    to_binary(&QueryResponse { message })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use cosmwasm_std::{coins, from_binary, HumanAddr};

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
        let res = query(&deps, QueryMsg::Query {});
        assert!(res.is_ok(), "query failed: {}", res.err().unwrap());
        let value: QueryResponse = from_binary(&res.unwrap()).unwrap();
        assert_eq!("congratulations", value.message);
    }

    #[test]
    fn store_input() {
        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env("creator", &coins(1000, "earth"));
        let init_msg = InitMsg {
            gateway_address: HumanAddr("fake address".to_string()),
            gateway_hash: "fake code hash".to_string(),
            gateway_key: Binary(b"fake key".to_vec()),
        };
        init(&mut deps, env.clone(), init_msg).unwrap();

        let message = PrivContractHandleMsg {
            input_values: "{\"address\":\"0x249C8753A9CB2a47d97A11D94b2179023B7aBCca\",\"name\":\"bob\",\"worth\":2000,\"match_addr\":\"0xb607FE9eF481950D47AEdf71ccB904Ff97806cF7\"}".to_string(),
            handle: "submit_player".to_string(),
            task_id: 1,
            input_hash: to_binary(&"".to_string()).unwrap(),
            signature: to_binary(&"".to_string()).unwrap(),
        };
        let handle_msg = HandleMsg::Input { message };

        let handle_response = handle(&mut deps, env.clone(), handle_msg).unwrap();
        let result = &handle_response.log[0].value;
        assert_eq!(result, "private computation complete                                                                                                                                                                                                                                    ");
    }

    #[test]
    fn compare() {
        let player1 = Millionaire::new("Alice".to_string(), 1000000, "0x249C8753A9CB2a47d97A11D94b2179023B7aBCca".to_string());
        let player2 = Millionaire::new("Bob".to_string(), 2000000, "0xb607FE9eF481950D47AEdf71ccB904Ff97806cF7".to_string());
        let response = try_compare(player1, player2);
        assert_eq!("{\"result\":\"The richer of Alice and Bob is Bob\"}", response);

        let player1 = Millionaire::new("Alice".to_string(), 5000000, "0x249C8753A9CB2a47d97A11D94b2179023B7aBCca".to_string());
        let player2 = Millionaire::new("Bob".to_string(), 2000000, "0xb607FE9eF481950D47AEdf71ccB904Ff97806cF7".to_string());
        let response = try_compare(player1, player2);
        assert_eq!("{\"result\":\"The richer of Alice and Bob is Alice\"}", response);

        let player1 = Millionaire::new("Alice".to_string(), 1000000, "0x249C8753A9CB2a47d97A11D94b2179023B7aBCca".to_string());
        let player2 = Millionaire::new("Bob".to_string(), 1000000, "0xb607FE9eF481950D47AEdf71ccB904Ff97806cF7".to_string());
        let response = try_compare(player1, player2);
        assert_eq!("{\"result\":\"It's a tie!\"}", response);
    }
}
