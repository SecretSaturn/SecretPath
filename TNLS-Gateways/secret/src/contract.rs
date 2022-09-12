use cosmwasm_std::{
    log, plaintext_log, to_binary, Api, Binary, Env, Extern, HandleResponse, HandleResult,
    HumanAddr, InitResponse, InitResult, Querier, QueryResult, StdError, Storage,
};
use secret_toolkit::{
    crypto::secp256k1::{PrivateKey, PublicKey},
    crypto::{sha_256, Prng},
    utils::{pad_handle_result, pad_query_result, HandleCallback},
};

use crate::{
    msg::{
        ContractStatus, HandleMsg, InitMsg, InputResponse, PostExecutionMsg, PreExecutionMsg,
        PublicKeyResponse, QueryMsg, ResponseStatus::Success, SecretMsg,
    },
    state::{
        config, config_read, creator_address, map2inputs, map2inputs_read, my_address, prng,
        KeyPair, State, TaskInfo,
    },
    PrivContractHandleMsg,
};

/// pad handle responses and log attributes to blocks of 256 bytes to prevent leaking info based on
/// response size
pub const BLOCK_SIZE: usize = 256;

#[cfg(feature = "contract")]
////////////////////////////////////// Init ///////////////////////////////////////
/// Returns InitResult
///
/// Initializes the contract
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `msg` - InitMsg passed in with the instantiation message
pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: InitMsg,
) -> InitResult {
    // Save this contract's address
    let my_address_raw = &deps.api.canonical_address(&env.contract.address)?;
    my_address(&mut deps.storage).save(my_address_raw)?;

    // Save the address of the contract's creator
    let creator_raw = deps.api.canonical_address(&env.message.sender)?;
    creator_address(&mut deps.storage).save(&creator_raw)?;

    // Set admin address if provided, or else use creator address
    let admin_raw = msg
        .admin
        .map(|a| deps.api.canonical_address(&a))
        .transpose()?
        .unwrap_or(creator_raw);

    // Save both key pairs
    let state = State {
        admin: admin_raw,
        keyed: false,
        tx_cnt: 0,
        status: ContractStatus::Normal.to_u8(),
        encryption_keys: KeyPair::default(),
        signing_keys: KeyPair::default(),
    };

    config(&mut deps.storage).save(&state)?;

    let rng_msg = SecretMsg::CreateRn {
        cb_msg: Binary(vec![]),
        entropy: msg.entropy,
        max_blk_delay: None,
        purpose: Some("secret gateway entropy".to_string()),
        receiver_addr: Some(env.contract.address),
        receiver_code_hash: env.contract_code_hash,
    }
    .to_cosmos_msg(msg.rng_hash, msg.rng_addr, None)?;

    Ok(InitResponse {
        messages: vec![rng_msg],
        log: vec![
            log("encryption_pubkey", &state.encryption_keys.pk), // should be empty
            log("signing_pubkey", &state.signing_keys.pk),       // should be empty
        ],
    })
}

#[cfg(feature = "contract")]
///////////////////////////////////// Handle //////////////////////////////////////
/// Returns HandleResult
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `msg` - HandleMsg passed in with the execute message
pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> HandleResult {
    match msg {
        HandleMsg::KeyGen { rng_hash, rng_addr } => {
            pad_handle_result(try_fulfill_rn(deps, env, rng_hash, rng_addr), BLOCK_SIZE)
        }
        HandleMsg::ReceiveFRn {
            cb_msg: _,
            purpose: _,
            rn,
        } => pad_handle_result(create_gateway_keys(deps, env, rn), BLOCK_SIZE),
        HandleMsg::Input { inputs } => {
            pad_handle_result(pre_execution(deps, env, inputs), BLOCK_SIZE)
        }
        HandleMsg::Output { outputs } => post_execution(deps, env, outputs),
    }
}

fn try_fulfill_rn<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    rng_hash: String,
    rng_addr: HumanAddr,
) -> HandleResult {
    // load config
    let state = config_read(&deps.storage).load()?;

    // check if the keys have already been created
    if state.keyed {
        return Err(StdError::generic_err(
            "keys have already been created".to_string(),
        ));
    }

    let fulfill_rn_msg = SecretMsg::FulfillRn {
        creator_addr: env.contract.address,
        purpose: Some("secret gateway entropy".to_string()),
        receiver_code_hash: env.contract_code_hash,
    }
    .to_cosmos_msg(rng_hash, rng_addr, None)?;

    Ok(HandleResponse {
        messages: vec![fulfill_rn_msg],
        log: vec![],
        data: None,
    })
}

fn create_gateway_keys<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    prng_seed: [u8; 32],
) -> HandleResult {
    // load config
    let state = config_read(&deps.storage).load()?;

    // check if the keys have already been created
    if state.keyed {
        return Err(StdError::generic_err(
            "keys have already been created".to_string(),
        ));
    }

    // Generate secp256k1 key pair for encryption
    let (secret, public, new_prng_seed) = generate_keypair(&env, prng_seed.to_vec(), None)?;
    let encryption_keys = KeyPair {
        sk: Binary(secret.serialize().to_vec()), // private key is 32 bytes,
        pk: Binary(public.serialize_compressed().to_vec()), // public key is 33 bytes
    };

    // Generate secp256k1 key pair for signing messages
    let (secret, public, new_prng_seed) = generate_keypair(&env, new_prng_seed, None)?;
    let signing_keys = KeyPair {
        sk: Binary(secret.serialize().to_vec()), // private key is 32 bytes,
        pk: Binary(public.serialize_compressed().to_vec()), // public key is 33 bytes
    };

    config(&mut deps.storage).update(|mut state| {
        state.keyed = true;
        state.encryption_keys = encryption_keys;
        state.signing_keys = signing_keys;
        Ok(state)
    })?;
    prng(&mut deps.storage).save(&new_prng_seed)?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![
            log("encryption_pubkey", &state.encryption_keys.pk),
            log("signing_pubkey", &state.signing_keys.pk),
        ],
        data: None,
    })
}

fn pre_execution<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: Env,
    msg: PreExecutionMsg,
) -> HandleResult {
    // verify that signature is correct
    msg.verify(deps)?;

    // load config
    let config = config_read(&deps.storage).load()?;

    // decrypt payload
    let payload = msg.decrypt_payload(config.encryption_keys.sk)?;
    let input_values = payload.data;
    let input_hash = sha_256(input_values.as_bytes());

    // verify the internal verification key matches the user address
    if payload.sender != msg.sender_info {
        return Err(StdError::generic_err("verification key mismatch"));
    }
    // verify the routing info matches the internally stored routing info
    if msg.routing_info != payload.routing_info {
        return Err(StdError::generic_err("routing info mismatch"));
    }

    // create a task information store
    let task_info = TaskInfo {
        payload: msg.payload, // storing the ENCRYPTED payload
        input_hash,           // storing the DECRYPTED inputs, hashed
        source_network: msg.source_network,
    };

    // map task ID to inputs hash
    map2inputs(&mut deps.storage).insert(&msg.task_id.to_le_bytes(), task_info)?;

    // load key and sign(task ID + input values)
    let mut signing_key_bytes = [0u8; 32];
    signing_key_bytes.copy_from_slice(config.signing_keys.sk.as_slice());

    // this signature is used in production
    #[cfg(target_arch = "wasm32")]
    let signature = PrivateKey::parse(&signing_key_bytes)?
        .sign(&input_hash, deps.api)
        .serialize()
        .to_vec();

    // this signature is only used during unit testing
    #[cfg(not(target_arch = "wasm32"))]
    let signature = {
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&signing_key_bytes).unwrap();
        let message = secp256k1::Message::from_slice(&input_hash)
            .map_err(|err| StdError::generic_err(err.to_string()))?;
        secp.sign_ecdsa(&message, &sk).serialize_compact().to_vec()
    };

    // construct the message to send to the destination contract
    let private_contract_msg = SecretMsg::Input {
        message: PrivContractHandleMsg {
            input_values,
            handle: msg.handle,
            task_id: msg.task_id,
            input_hash: Binary(input_hash.to_vec()),
            signature: Binary(signature),
        },
    };
    let cosmos_msg = private_contract_msg.to_cosmos_msg(
        msg.routing_info.hash,
        msg.routing_info.address,
        None,
    )?;

    Ok(HandleResponse {
        messages: vec![cosmos_msg],
        log: vec![
            plaintext_log("task_id", &msg.task_id),
            plaintext_log("status", "sent to private contract"),
        ],
        data: Some(to_binary(&InputResponse { status: Success })?),
    })
}

fn post_execution<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: Env,
    msg: PostExecutionMsg,
) -> HandleResult {
    // load task ID information (remember this is decrypted)
    let task_info = map2inputs_read(&deps.storage).load(&msg.task_id.to_le_bytes())?;

    // verify that input hash is correct one for Task ID
    if msg.input_hash.as_slice() != task_info.input_hash.to_vec() {
        return Err(StdError::generic_err("input hash does not match task id"));
    }

    let routing_hash = sha_256(task_info.source_network.as_bytes());
    let payload_hash = sha_256(task_info.payload.as_slice());
    let task_hash = sha_256(&msg.task_id.to_le_bytes());

    // create message hash of (result + payload + inputs)
    let data = [
        msg.result.as_bytes(),
        task_info.payload.as_slice(),
        &task_info.input_hash,
    ]
    .concat();
    let result_hash = sha_256(&data);

    // load this gateway's signing key
    let private_key = config_read(&deps.storage).load()?.signing_keys.sk;
    let mut signing_key_bytes = [0u8; 32];
    signing_key_bytes.copy_from_slice(private_key.as_slice());

    // used in production
    #[cfg(target_arch = "wasm32")]
    let (routing_signature, payload_signature, result_signature, task_signature) = {
        let sk = PrivateKey::parse(&signing_key_bytes)?;

        let routing_signature = sk.sign(&routing_hash, deps.api).serialize().to_vec();
        let payload_signature = sk.sign(&payload_hash, deps.api).serialize().to_vec();
        let result_signature = sk.sign(&result_hash, deps.api).serialize().to_vec();
        let task_signature = sk.sign(&task_hash, deps.api).serialize().to_vec();

        (
            routing_signature,
            payload_signature,
            result_signature,
            task_signature,
        )
    };

    // used in unit testing
    #[cfg(not(target_arch = "wasm32"))]
    let (routing_signature, payload_signature, result_signature, task_signature) = {
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&signing_key_bytes).unwrap();

        let routing_message = secp256k1::Message::from_slice(&routing_hash)
            .map_err(|err| StdError::generic_err(err.to_string()))?;
        let routing_signature = secp
            .sign_ecdsa(&routing_message, &sk)
            .serialize_compact()
            .to_vec();

        let payload_message = secp256k1::Message::from_slice(&payload_hash)
            .map_err(|err| StdError::generic_err(err.to_string()))?;
        let payload_signature = secp
            .sign_ecdsa(&payload_message, &sk)
            .serialize_compact()
            .to_vec();

        let result_message = secp256k1::Message::from_slice(&result_hash)
            .map_err(|err| StdError::generic_err(err.to_string()))?;
        let result_signature = secp
            .sign_ecdsa(&result_message, &sk)
            .serialize_compact()
            .to_vec();

        let task_message = secp256k1::Message::from_slice(&task_hash)
            .map_err(|err| StdError::generic_err(err.to_string()))?;
        let task_signature = secp
            .sign_ecdsa(&task_message, &sk)
            .serialize_compact()
            .to_vec();

        (
            routing_signature,
            payload_signature,
            result_signature,
            task_signature,
        )
    };

    // create hash of entire packet (used to verify the message wasn't modified in transit)
    let data = [
        "secret".as_bytes(),                 // source network
        task_info.source_network.as_bytes(), // routing info
        &routing_hash,                       // routing info message
        &routing_signature,                  // routing info signature
        task_info.payload.as_slice(),        // payload (original encrypted payload)
        &payload_hash,                       // payload message
        &payload_signature,                  // payload signature
        msg.result.as_bytes(),               // result
        &result_hash,                        // result message
        &result_signature,                   // result signature
    ]
    .concat();
    let packet_hash = sha_256(&data);

    // used in production
    #[cfg(target_arch = "wasm32")]
    let packet_signature = {
        PrivateKey::parse(&signing_key_bytes)?
            .sign(&packet_hash, deps.api)
            .serialize()
            .to_vec()
    };

    // used in unit testing
    #[cfg(not(target_arch = "wasm32"))]
    let packet_signature = {
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&signing_key_bytes).unwrap();

        let packet_message = secp256k1::Message::from_slice(&packet_hash)
            .map_err(|err| StdError::generic_err(err.to_string()))?;

        secp.sign_ecdsa(&packet_message, &sk)
            .serialize_compact()
            .to_vec()
    };

    Ok(HandleResponse {
        messages: vec![],
        log: vec![
            plaintext_log("source_network", "secret"),
            plaintext_log("routing_info", task_info.source_network),
            plaintext_log("routing_info_hash", Binary(routing_hash.to_vec())),
            plaintext_log("routing_info_signature", Binary(routing_signature)),
            plaintext_log("payload", task_info.payload),
            plaintext_log("payload_hash", Binary(payload_hash.to_vec())),
            plaintext_log("payload_signature", Binary(payload_signature)),
            plaintext_log("result", msg.result),
            plaintext_log("result_hash", Binary(result_hash.to_vec())),
            plaintext_log("result_signature", Binary(result_signature)),
            plaintext_log("packet_hash", Binary(packet_hash.to_vec())),
            plaintext_log("packet_signature", Binary(packet_signature)),
            plaintext_log("task_id", msg.task_id),
            plaintext_log("task_id_hash", Binary(task_hash.to_vec())),
            plaintext_log("task_id_signature", Binary(task_signature)),
        ],
        data: None,
    })
}

#[cfg(feature = "contract")]
/////////////////////////////////////// Query /////////////////////////////////////
/// Returns QueryResult
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `msg` - QueryMsg passed in with the query call
pub fn query<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>, msg: QueryMsg) -> QueryResult {
    let response = match msg {
        QueryMsg::GetPublicKey {} => query_public_key(deps),
    };
    pad_query_result(response, BLOCK_SIZE)
}

fn query_public_key<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>) -> QueryResult {
    let state: State = config_read(&deps.storage).load()?;
    to_binary(&PublicKeyResponse {
        key: state.encryption_keys.pk,
    })
}

/////////////////////////////////////// Helpers /////////////////////////////////////

/// Returns (PublicKey, StaticSecret, Vec<u8>)
///
/// generates a public and privite key pair and generates a new PRNG_SEED with or without user entropy.
///
/// # Arguments
///
/// * `env` - contract's environment to be used for randomization
/// * `prng_seed` - required prng seed for randomization
/// * `user_entropy` - optional random string input by the user
pub fn generate_keypair(
    env: &Env,
    prng_seed: Vec<u8>,
    user_entropy: Option<String>,
) -> Result<(PrivateKey, PublicKey, Vec<u8>), StdError> {
    // generate new rng seed
    let new_prng_bytes: [u8; 32] = match user_entropy {
        Some(s) => new_entropy(env, prng_seed.as_ref(), s.as_bytes()),
        None => new_entropy(env, prng_seed.as_ref(), prng_seed.as_ref()),
    };

    // generate and return key pair
    let mut rng = Prng::new(prng_seed.as_ref(), new_prng_bytes.as_ref());
    let sk = PrivateKey::parse(&rng.rand_bytes())?;
    let pk = sk.pubkey();

    Ok((sk, pk, new_prng_bytes.to_vec()))
}

/// Returns [u8;32]
///
/// generates new entropy from block data, does not save it to the contract.
///
/// # Arguments
///
/// * `env` - Env of contract's environment
/// * `seed` - (user generated) seed for rng
/// * `entropy` - Entropy seed saved in the contract
pub fn new_entropy(env: &Env, seed: &[u8], entropy: &[u8]) -> [u8; 32] {
    // 16 here represents the lengths in bytes of the block height and time.
    let entropy_len = 16 + env.message.sender.len() + entropy.len();
    let mut rng_entropy = Vec::with_capacity(entropy_len);
    rng_entropy.extend_from_slice(&env.block.height.to_be_bytes());
    rng_entropy.extend_from_slice(&env.block.time.to_be_bytes());
    rng_entropy.extend_from_slice(env.message.sender.0.as_bytes());
    rng_entropy.extend_from_slice(entropy);

    let mut rng = Prng::new(seed, &rng_entropy);

    rng.rand_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use cosmwasm_std::{from_binary, Binary, Empty, HumanAddr};
    use secret_toolkit::utils::types::Contract;

    use chacha20poly1305::aead::{Aead, NewAead};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    use secp256k1::{ecdh::SharedSecret, Message, Secp256k1, SecretKey};

    const OWNER: &str = "admin0001";
    const SOMEBODY: &str = "somebody";

    #[track_caller]
    fn setup_test_case<S: Storage, A: Api, Q: Querier>(
        deps: &mut Extern<S, A, Q>,
    ) -> Result<InitResponse<Empty>, StdError> {
        // Instantiate a contract with entropy
        let admin = Some(HumanAddr(OWNER.to_owned()));
        let entropy = "secret".to_owned();
        let rng_hash = "string".to_string();
        let rng_addr = HumanAddr("address".to_string());

        let init_msg = InitMsg {
            admin,
            entropy,
            rng_hash,
            rng_addr,
        };
        init(deps, mock_env(OWNER, &[]), init_msg)
    }

    #[track_caller]
    fn get_gateway_key<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>) -> Binary {
        let query_msg = QueryMsg::GetPublicKey {};
        let query_result = query(&deps, query_msg);
        let query_answer: PublicKeyResponse = from_binary(&query_result.unwrap()).unwrap();
        let gateway_pubkey = query_answer.key;
        gateway_pubkey
    }

    #[test]
    fn test_init() {
        let mut deps = mock_dependencies(20, &[]);

        let response = setup_test_case(&mut deps).unwrap();
        assert_eq!(2, response.log.len());
        let pubkey = Binary::from_base64(&response.log[0].value).unwrap();
        assert_eq!(pubkey.len(), 0);
    }

    #[test]
    fn test_query() {
        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env(SOMEBODY, &[]);

        // initialize
        setup_test_case(&mut deps).unwrap();

        // mock scrt-rng message
        let mut rng = Prng::new(&[1, 2, 3], &[4, 5, 6]);
        let fake_msg = HandleMsg::ReceiveFRn {
            cb_msg: Binary(vec![]),
            purpose: None,
            rn: rng.rand_bytes(),
        };
        handle(&mut deps, env, fake_msg).unwrap();

        // query
        let msg = QueryMsg::GetPublicKey {};
        let res = query(&deps, msg);
        assert!(res.is_ok(), "query failed: {}", res.err().unwrap());
        let value: PublicKeyResponse = from_binary(&res.unwrap()).unwrap();
        assert_eq!(value.key.as_slice().len(), 33);
    }

    #[test]
    fn test_pre_execution() {
        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env(OWNER, &[]);

        // initialize
        setup_test_case(&mut deps).unwrap();

        // mock scrt-rng message
        let mut rng = Prng::new(&[1, 2, 3], &[4, 5, 6]);
        let fake_msg = HandleMsg::ReceiveFRn {
            cb_msg: Binary(vec![]),
            purpose: None,
            rn: rng.rand_bytes(),
        };
        handle(&mut deps, env.clone(), fake_msg).unwrap();

        // get gateway public encryption key
        let gateway_pubkey = get_gateway_key(&deps);

        // mock key pair
        let secp = Secp256k1::new();
        let secret_key = Key::from_slice(b"an example very very secret key."); // 32-bytes
        let secret_key = SecretKey::from_slice(secret_key).unwrap();
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

        // create shared key from user private + gateway public
        let gateway_pubkey = secp256k1::PublicKey::from_slice(gateway_pubkey.as_slice()).unwrap();
        let shared_key = SharedSecret::new(&gateway_pubkey, &secret_key);

        // mock Payload
        let data = "{\"fingerprint\": \"0xF9BA143B95FF6D82\", \"location\": \"Menlo Park, CA\"}"
            .to_string();
        let routing_info = Contract {
            address: HumanAddr::from("secret19zpyd046u4swqpksr3n44cej4j8pg6ahw95y85".to_string()),
            hash: "2a2fbe493ef25b536bbe0baa3917b51e5ba092e14bd76abf50a59526e2789be3".to_string(),
        };
        let sender_info = Sender {
            address: HumanAddr::from("some eth address".to_string()),
            public_key: Binary(public_key.serialize().to_vec()),
        };
        let payload = Payload {
            data,
            routing_info: routing_info.clone(),
            sender: sender_info.clone(),
        };
        let serialized_payload = to_binary(&payload).unwrap();

        // encrypt the payload
        let cipher = ChaCha20Poly1305::new_from_slice(shared_key.as_ref())
            .map_err(|_err| StdError::generic_err("could not create cipher".to_string()))
            .unwrap();
        let nonce = Nonce::from_slice(b"unique nonce"); // 12-bytes; unique per message
        let encrypted_payload = cipher
            .encrypt(nonce, serialized_payload.as_slice())
            .unwrap();

        // sign the payload
        let payload_hash = sha_256(serialized_payload.as_slice());
        let message = Message::from_slice(&payload_hash).unwrap();
        let payload_signature = secp.sign_ecdsa(&message, &secret_key);

        // wrong sender info
        let wrong_sender_info = Sender {
            address: HumanAddr::from("wrong eth address".to_string()),
            public_key: Binary(public_key.serialize().to_vec()),
        };

        // test internal user address does not match
        let pre_execution_msg = PreExecutionMsg {
            task_id: 1,
            handle: "test".to_string(),
            routing_info: routing_info.clone(),
            sender_info: wrong_sender_info,
            payload: Binary(encrypted_payload.clone()),
            nonce: Binary(b"unique nonce".to_vec()),
            payload_hash: Binary(payload_hash.to_vec()),
            payload_signature: Binary(payload_signature.serialize_compact().to_vec()),
            source_network: "ethereum".to_string(),
        };
        let handle_msg = HandleMsg::Input {
            inputs: pre_execution_msg,
        };
        let err = handle(&mut deps, env.clone(), handle_msg).unwrap_err();
        assert_eq!(err, StdError::generic_err("verification key mismatch"));

        // wrong routing info
        let wrong_routing_info = Contract {
            address: HumanAddr::from("secret13rcx3p8pxf0ttuvxk6czwu73sdccfz4w6e27fd".to_string()),
            hash: "19438bf0cdf555c6472fb092eae52379c499681b36e47a2ef1c70f5269c8f02f".to_string(),
        };

        // test internal routing info does not match
        let pre_execution_msg = PreExecutionMsg {
            task_id: 1,
            handle: "test".to_string(),
            routing_info: wrong_routing_info.clone(),
            sender_info: sender_info.clone(),
            payload: Binary(encrypted_payload.clone()),
            nonce: Binary(b"unique nonce".to_vec()),
            payload_hash: Binary(payload_hash.to_vec()),
            payload_signature: Binary(payload_signature.serialize_compact().to_vec()),
            source_network: "ethereum".to_string(),
        };
        let handle_msg = HandleMsg::Input {
            inputs: pre_execution_msg,
        };
        let err = handle(&mut deps, env.clone(), handle_msg).unwrap_err();
        assert_eq!(err, StdError::generic_err("routing info mismatch"));

        // test proper input handle
        let pre_execution_msg = PreExecutionMsg {
            task_id: 1,
            handle: "test".to_string(),
            routing_info,
            sender_info,
            payload: Binary(encrypted_payload),
            nonce: Binary(b"unique nonce".to_vec()),
            payload_hash: Binary(payload_hash.to_vec()),
            payload_signature: Binary(payload_signature.serialize_compact().to_vec()),
            source_network: "ethereum".to_string(),
        };
        let handle_msg = HandleMsg::Input {
            inputs: pre_execution_msg,
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

    #[test]
    fn test_post_execution() {
        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env(OWNER, &[]);

        // initialize
        setup_test_case(&mut deps).unwrap();

        // mock scrt-rng message
        let mut rng = Prng::new(&[1, 2, 3], &[4, 5, 6]);
        let fake_msg = HandleMsg::ReceiveFRn {
            cb_msg: Binary(vec![]),
            purpose: None,
            rn: rng.rand_bytes(),
        };
        handle(&mut deps, env.clone(), fake_msg).unwrap();

        // get gateway public encryption key
        let gateway_pubkey = get_gateway_key(&deps);

        // mock key pair
        let secp = Secp256k1::new();
        let secret_key = Key::from_slice(b"an example very very secret key."); // 32-bytes
        let secret_key = SecretKey::from_slice(secret_key).unwrap();
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

        // create shared key from user private + gateway public
        let gateway_pubkey = secp256k1::PublicKey::from_slice(gateway_pubkey.as_slice()).unwrap();
        let shared_key = SharedSecret::new(&gateway_pubkey, &secret_key);

        // mock Payload
        let data = "{\"fingerprint\": \"0xF9BA143B95FF6D82\", \"location\": \"Menlo Park, CA\"}"
            .to_string();
        let routing_info = Contract {
            address: HumanAddr::from("secret19zpyd046u4swqpksr3n44cej4j8pg6ahw95y85".to_string()),
            hash: "2a2fbe493ef25b536bbe0baa3917b51e5ba092e14bd76abf50a59526e2789be3".to_string(),
        };
        let sender_info = Sender {
            address: HumanAddr::from("some eth address".to_string()),
            public_key: Binary(public_key.serialize().to_vec()),
        };
        let payload = Payload {
            data: data.clone(),
            routing_info: routing_info.clone(),
            sender: sender_info.clone(),
        };
        let serialized_payload = to_binary(&payload).unwrap();

        // encrypt the payload
        let cipher = ChaCha20Poly1305::new_from_slice(shared_key.as_ref())
            .map_err(|_err| StdError::generic_err("could not create cipher".to_string()))
            .unwrap();
        let nonce = Nonce::from_slice(b"unique nonce"); // 12-bytes; unique per message
        let encrypted_payload = cipher
            .encrypt(nonce, serialized_payload.as_slice())
            .expect("encryption failure!"); // NOTE: handle this error to avoid panics!

        // sign the payload
        let payload_hash = sha_256(serialized_payload.as_slice());
        let message = Message::from_slice(&payload_hash).unwrap();
        let payload_signature = secp.sign_ecdsa(&message, &secret_key);

        // execute input handle
        let pre_execution_msg = PreExecutionMsg {
            task_id: 1,
            handle: "test".to_string(),
            routing_info,
            sender_info,
            payload: Binary(encrypted_payload),
            nonce: Binary(b"unique nonce".to_vec()),
            payload_hash: Binary(payload_hash.to_vec()),
            payload_signature: Binary(payload_signature.serialize_compact().to_vec()),
            source_network: "ethereum".to_string(),
        };
        let handle_msg = HandleMsg::Input {
            inputs: pre_execution_msg.clone(),
        };
        handle(&mut deps, env.clone(), handle_msg).unwrap();

        // test incorrect input_hash
        let wrong_post_execution_msg = PostExecutionMsg {
            result: "{\"answer\": 42}".to_string(),
            task_id: 1,
            input_hash: Binary(sha_256("wrong data".as_bytes()).to_vec()),
        };
        let handle_msg = HandleMsg::Output {
            outputs: wrong_post_execution_msg,
        };
        let err = handle(&mut deps, env.clone(), handle_msg).unwrap_err();
        assert_eq!(
            err,
            StdError::generic_err("input hash does not match task id")
        );

        // test output handle
        let post_execution_msg = PostExecutionMsg {
            result: "{\"answer\": 42}".to_string(),
            task_id: 1,
            input_hash: Binary(sha_256(&data.as_bytes()).to_vec()),
        };

        let handle_msg = HandleMsg::Output {
            outputs: post_execution_msg,
        };
        let handle_result = handle(&mut deps, env.clone(), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle failed: {}",
            handle_result.err().unwrap()
        );
        let logs = handle_result.unwrap().log;

        assert_eq!(logs[0].value, "secret".to_string());
        assert_eq!(logs[1].value, "ethereum".to_string());
        assert_eq!(base64::decode(logs[2].value.clone()).unwrap().len(), 32);
        assert_eq!(base64::decode(logs[3].value.clone()).unwrap().len(), 64);
        assert_eq!(logs[4].value, pre_execution_msg.payload.to_base64());
        assert_eq!(base64::decode(logs[5].value.clone()).unwrap().len(), 32);
        assert_eq!(base64::decode(logs[6].value.clone()).unwrap().len(), 64);
        assert_eq!(logs[7].value, "{\"answer\": 42}".to_string());
        assert_eq!(base64::decode(logs[8].value.clone()).unwrap().len(), 32);
        assert_eq!(base64::decode(logs[9].value.clone()).unwrap().len(), 64);
        assert_eq!(base64::decode(logs[10].value.clone()).unwrap().len(), 32);
        assert_eq!(base64::decode(logs[11].value.clone()).unwrap().len(), 64);
        assert_eq!(logs[12].value, "1".to_string());
        assert_eq!(base64::decode(logs[13].value.clone()).unwrap().len(), 32);
        assert_eq!(base64::decode(logs[14].value.clone()).unwrap().len(), 64);
    }
}
