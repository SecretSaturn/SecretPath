use cosmwasm_std::{
    plaintext_log, to_binary, Api, Env, Extern, HandleResponse, HandleResult, InitResponse,
    InitResult, Querier, QueryResult, Storage,
};

use crate::msg::{HandleMsg, InitMsg, QueryMsg, QueryResponse, Response, ResponseStatus::Success};

pub fn init<S: Storage, A: Api, Q: Querier>(
    _deps: &mut Extern<S, A, Q>,
    _env: Env,
    _msg: InitMsg,
) -> InitResult {
    Ok(InitResponse {
        messages: vec![],
        log: vec![plaintext_log("message", "contract initialized")],
    })
}

pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> HandleResult {
    match msg {
        HandleMsg::Handle { input } => try_handle(deps, env, input),
    }
}

fn try_handle<S: Storage, A: Api, Q: Querier>(
    _deps: &mut Extern<S, A, Q>,
    _env: Env,
    msg: String,
) -> HandleResult {
    Ok(HandleResponse {
        messages: vec![],
        log: vec![
            plaintext_log("source_network", "secret"),
            plaintext_log("routing_info", "ethereum"),
            plaintext_log("routing_info_hash", "tg173TNM03aNQ/FKBcf+fohrpby3fhBkUwBS/tGj8UU="),
            plaintext_log("routing_info_signature", "dWdrin5Mv5Szt4Jif7n6oqx45D+A9i4VDlnFlYx+LKBVIFpVeF010WbAiUC3K0QnaUK+xZ3li8L4ANBaZszD1A=="),
            plaintext_log("payload", "1C+pS0+JF7v7I+9kx933nGrZZNU6NXXJrumMtFLEN/aEr3EZ2DXJH6/I3W5zkgAlwJh6Mt0Wjl87U7RSIegtrMeehoJKoqlSMlRLSZGJ/l5YKBJhDmlzcZ+nT6VqrW5IuAW9sGhX/be9FSbY/qBgDkzkUck2WaeqFlnXCv3l+ovam9JrT90yG0rrw+WH6g8NPA4C4KeMlATmJc/X53mO3x1lVlBAE4eTQLxtBFtxtva8zr8auNrzOKoqX0nqIq+p0E5vERFjgwPmOZ6IIWzMNoVw/9Grq1acakMPMo6va3OZlY0jghsvrkkcW1AihwmqgJOApsi+aMlVXkdfLz1Cf0l63mWcxIlEC7mPBSGHeOB9bZkvh6aNy+4sdZVdv8KaXQ72ZHo3Fw6Pxpf6zyAXHozFIsqtqE+SR5ygTmz7QMJGmzhymdmIuAySWCaoJA6nG+/m78SnndwMlj9QX7r8GOxJjASY5h2JDbKD5k1O8NrH4GpTWQVgZ/VAPqqwNLaTkcAFIdIfj80LS1fobMErys+MDnAEGeFbRQo6tRIrXBVA9RhAMcDLzSQplKB21L/4MEagDbMhB34iCxhNeSgY3csgkvsJRw0tyw=="),
            plaintext_log("payload_hash", "UkqRIveb4P0KUgAEeNE8/z5OPNSs8QOynkJkA4UpucI="),
            plaintext_log("payload_signature", "QBXH9gS73HijN4VADdfJxMFRPot8Q6pKMTqsmSPeJhxU2xgt8b4LMP9H8xggc4gH95ux4tVaBy/oRgNdPPEYoQ=="),
            plaintext_log("result", msg),   // actually the input
            plaintext_log("result_hash", "lfYReCYU+mQrsimU8aTf//T8nnGYvX9uaXxOLuCT9C4="),
            plaintext_log("result_signature", "ugX3ZxusQ7gcyF6h4BGikmp94AWTzi2hF8hLUvKdUW049Bjs7V+Y0kL3Fm/SQr3xRHhuzbinws5YlO1xroo5Mg=="),
            plaintext_log("packet_hash", "8nhN0kHYHDgAtsTL/BScyo2sJMtdP2D1Qd/OxcyHcMk="),
            plaintext_log("packet_signature", "53le1sTYJV6YNXKUqsl0gVrNBXFvjha1gqvtXgxfi1wW4LLhRYw80P/gRXpnfxQAecdzuoASmUHHu9/Gjmn0Rw=="),
            plaintext_log("task_id", "1"),
            plaintext_log("task_id_hash", "fJ+hNtRBP6YXNjfog7aZjTLh1nX4jN3/ncvPMxgg9Lg="),
            plaintext_log("task_id_signature", "rf07n8JaG3sZe9Tm9IkLg16hx+O9YOdaVluKoqMz/flBtKxcrrHh3may97XWEyD6sRT18FoOOXkCw2FsB5VGOw=="),
        ],
        data: Some(to_binary(&Response { status: Success })?),
    })
}

pub fn query<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>, msg: QueryMsg) -> QueryResult {
    match msg {
        QueryMsg::Query {} => _query(deps),
    }
}

fn _query<S: Storage, A: Api, Q: Querier>(_deps: &Extern<S, A, Q>) -> QueryResult {
    to_binary(&QueryResponse {
        response: "congratulations".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use cosmwasm_std::{StdError, Empty};

    const SOMEBODY: &str = "somebody";

    fn setup_test_case<S: Storage, A: Api, Q: Querier>(
        deps: &mut Extern<S, A, Q>,
    ) -> Result<InitResponse<Empty>, StdError> {
        let init_msg = InitMsg {};
        init(deps, mock_env(SOMEBODY, &[]), init_msg)
    }

    #[test]
    fn test_init() {
        let mut deps = mock_dependencies(20, &[]);
        let response = setup_test_case(&mut deps).unwrap();
        assert_eq!(1, response.log.len());
    }

    #[test]
    fn test_handle() {
        let mut deps = mock_dependencies(20, &[]);
        setup_test_case(&mut deps).unwrap();

        let handle_msg = HandleMsg::Handle {
            input: "{\"hello\":\"world\"}".to_string(),
        };
        let response = handle(&mut deps, mock_env(SOMEBODY, &[]), handle_msg).unwrap();
        assert_eq!(15, response.log.len());
    }
}
