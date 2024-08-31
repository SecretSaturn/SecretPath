use cosmwasm_std::{
    from_binary, entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError,
    StdResult,
};
use secret_toolkit::{
    crypto::secp256k1::{PrivateKey, PublicKey},
    crypto::{sha_256, ContractPrng},
    utils::{pad_handle_result, pad_query_result, HandleCallback},
};

use crate::{
    msg::{
        ExecuteMsg, InputResponse, InstantiateMsg, PostExecutionMsg, PreExecutionMsg,
        PublicKeyResponse, QueryMsg, ResponseStatus::Success, SecretMsg,
    },
    state::{KeyPair, State, Task, TaskInfo, ResultInfo, CONFIG, CREATOR, MY_ADDRESS, TASK_MAP, RESULT_MAP},
    PrivContractHandleMsg,
};

use hex::ToHex;
use sha3::{Digest, Keccak256};

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
#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    // Save this contract's address
    let my_address_raw = &deps.api.addr_canonicalize(env.contract.address.as_str())?;
    MY_ADDRESS.save(deps.storage, my_address_raw)?;

    // Save the address of the contract's creator
    let creator_raw = deps.api.addr_canonicalize(info.sender.as_str())?;
    CREATOR.save(deps.storage, &creator_raw)?;

    // Set admin address if provided, or else use creator address
    let admin_raw = msg
        .admin
        .map(|a| deps.api.addr_canonicalize(a.as_str()))
        .transpose()?
        .unwrap_or(creator_raw);

    // Save both key pairs
    let state = State {
        admin: admin_raw,
        keyed: false,
        encryption_keys: KeyPair::default(),
        signing_keys: KeyPair::default(),
    };

    CONFIG.save(deps.storage, &state)?;

    let _result = create_gateway_keys(deps, env);

    Ok(Response::new())
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
#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> StdResult<Response> {
    match msg {
        ExecuteMsg::Input { inputs } => {
            pad_handle_result(pre_execution(deps, env, inputs), BLOCK_SIZE)
        },
        ExecuteMsg::Output { outputs } => post_execution(deps, env, outputs),
        ExecuteMsg::RotateGatewayKeys {} => rotate_gateway_keys(deps, env, info),
    }
}

fn rotate_gateway_keys(deps: DepsMut, env: Env, info: MessageInfo) -> StdResult<Response> {
    // load config
    let state = CONFIG.load(deps.storage)?;

    let caller_raw = deps.api.addr_canonicalize(info.sender.as_str())?;

    // check if the keys have already been created
    if state.keyed {
        //if keys were have already been created, check if admin is calling this 
        if state.admin != caller_raw {
            return Err(StdError::generic_err(
                "keys have already been created and only admin is allowed to rotate gateway keys".to_string(),
            ));
        }
    }

    // Generate secp256k1 key pair for encryption
    let (secret, public) = generate_keypair(&env)?;
    let encryption_keys = KeyPair {
        sk: Binary(secret.serialize().to_vec()), // private key is 32 bytes,
        pk: Binary(public.serialize_compressed().to_vec()), // public key is 33 bytes
    };

    // Generate secp256k1 key pair for signing messages
    let (secret, public) = generate_keypair(&env)?;
    let signing_keys = KeyPair {
        sk: Binary(secret.serialize().to_vec()), // private key is 32 bytes,
        pk: Binary(public.serialize().to_vec()), // public key is 65 bytes
    };

    CONFIG.update(deps.storage, |mut state| {
        state.keyed = true;
        state.encryption_keys = encryption_keys.clone();
        state.signing_keys = signing_keys.clone();
        Ok(state)
    })?;

    let encryption_pubkey = encryption_keys.pk.to_base64();
    let signing_pubkey = signing_keys.pk.to_base64();

    Ok(Response::new()
        .add_attribute_plaintext("encryption_pubkey", encryption_pubkey)
        .add_attribute_plaintext("signing_pubkey", signing_pubkey))
}

fn create_gateway_keys(deps: DepsMut, env: Env) -> StdResult<Response> {
    // load config
    let state = CONFIG.load(deps.storage)?;

    // check if the keys have already been created
    if state.keyed {
        return Err(StdError::generic_err(
            "keys have already been created".to_string(),
        ));
    }

    // Generate secp256k1 key pair for encryption
    let (secret, public) = generate_keypair(&env)?;
    let encryption_keys = KeyPair {
        sk: Binary(secret.serialize().to_vec()), // private key is 32 bytes,
        pk: Binary(public.serialize_compressed().to_vec()), // public key is 33 bytes
    };

    // Generate secp256k1 key pair for signing messages
    let (secret, public) = generate_keypair(&env)?;
    let signing_keys = KeyPair {
        sk: Binary(secret.serialize().to_vec()), // private key is 32 bytes,
        pk: Binary(public.serialize().to_vec()), // public key is 65 bytes
    };

    CONFIG.update(deps.storage, |mut state| {
        state.keyed = true;
        state.encryption_keys = encryption_keys.clone();
        state.signing_keys = signing_keys.clone();
        Ok(state)
    })?;

    let encryption_pubkey = encryption_keys.pk.to_base64();
    let signing_pubkey = signing_keys.pk.to_base64();

    Ok(Response::new()
        .add_attribute_plaintext("encryption_pubkey", encryption_pubkey)
        .add_attribute_plaintext("signing_pubkey", signing_pubkey))
}

fn pre_execution(deps: DepsMut, _env: Env, msg: PreExecutionMsg) -> StdResult<Response> {
    // load config
    let config = CONFIG.load(deps.storage)?;

    // Attempt to decrypt the payload
    let decrypted_payload_result = msg.decrypt_payload(config.encryption_keys.sk);
    let mut unsafe_payload = false;
    let payload = match decrypted_payload_result {
        Ok(decrypted_payload) => {
            // If decryption is successful, attempt to verify
            match msg.verify(&deps) {
                Ok(_) => decrypted_payload, // Both decryption and verification succeeded
                Err(_) => {
                    unsafe_payload = true;
                    // Continue with the decrypted payload if only verification fails
                    decrypted_payload
                }
            }
        },
        Err(_) => {
            unsafe_payload = true;
            // If decryption fails, continue with the original, encrypted payload
            // We are not verifying the payload in this case as it's already deemed unsafe
            from_binary(&Binary::from(msg.payload.as_slice()))?
        },
    };
    
    // verify the internal verification key matches the user address
    if payload.user_key != msg.user_key {
        return Err(StdError::generic_err("verification key mismatch"));
    }
    // verify the routing info matches the internally stored routing info
    if msg.routing_info != payload.routing_info {
        return Err(StdError::generic_err("routing info mismatch"));
    }
    // verify the callback_gas_limit defined in the payload matches the msg callback_gas_limit
    if msg.callback_gas_limit != payload.callback_gas_limit {
        return Err(StdError::generic_err("callback gas limit mismatch"));
    }

    // check if the payload matches the payload hash
    let mut hasher = Keccak256::new();

    let prefix = "\x19Ethereum Signed Message:\n32".as_bytes();
    hasher.update(msg.payload.as_slice());
    let payload_hash_tmp = hasher.finalize_reset();
    hasher.update([prefix, &payload_hash_tmp].concat());
    let payload_hash_tmp = hasher.finalize();

    if msg.payload_hash.as_slice() != payload_hash_tmp.as_slice() {
        return Err(StdError::generic_err("Hashed Payload does not match payload hash"));
    }

    let new_task = Task {
        network: msg.source_network.clone(),
        task_id: msg.task_id.clone()
    }.clone();

    // check if the task wasn't executed before already
    let map_contains_task = TASK_MAP.contains(deps.storage, &new_task);

    if map_contains_task {
        return Err(StdError::generic_err("Task already exists, not executing again"));
    }

    let input_values = payload.data;

    // combine input values and task to create verification hash
    let unsafe_payload_bytes = if unsafe_payload { [1u8] } else { [0u8] };
    let input_hash = sha_256(&[input_values.as_bytes(), new_task.task_id.as_bytes(),&unsafe_payload_bytes].concat());

    // create a task information store
    let task_info = TaskInfo {
        payload: msg.payload, // store the payload
        payload_hash: msg.payload_hash,
        payload_signature: msg.payload_signature,
        decrypted_payload_data: input_values.clone(),
        routing_info: msg.routing_info.clone(),
        routing_code_hash: msg.routing_code_hash.clone(),
        user_pubkey: msg.user_pubkey,
        handle: msg.handle.clone(),
        nonce: msg.nonce,
        unsafe_payload, // store the unsafe_payload flag for later checks
        input_hash,     // store the input_values hashed together with task
        source_network: msg.source_network,
        user_address: payload.user_address.clone(),
        user_key: payload.user_key.clone(),
        callback_address: payload.callback_address.clone(),
        callback_selector: payload.callback_selector,
        callback_gas_limit: payload.callback_gas_limit
    };

    // map task to task info
    TASK_MAP.insert(deps.storage, &new_task, &task_info)?;

    // load this gateway's signing key
    let mut signing_key_bytes = [0u8; 32];
    signing_key_bytes.copy_from_slice(config.signing_keys.sk.as_slice());

    let signature = deps.api.secp256k1_sign(&input_hash, &signing_key_bytes)
        .map_err(|err| StdError::generic_err(err.to_string()))?;

    // construct the message to send to the destination contract
    let private_contract_msg = SecretMsg::Input {
        message: PrivContractHandleMsg {
            input_values,
            handle: msg.handle,
            user_address: payload.user_address,
            task: new_task.clone(),
            input_hash: Binary(input_hash.to_vec()),
            signature: Binary(signature),
        },
    };
    let cosmos_msg = private_contract_msg.to_cosmos_msg(
        msg.routing_code_hash,
        msg.routing_info.into_string(),
        None,
    )?;

    Ok(Response::new()
        .add_message(cosmos_msg)
        .add_attribute_plaintext("task_id", &new_task.task_id.to_string())
        .add_attribute_plaintext("status", "sent to private contract")
        .set_data(to_binary(&InputResponse { status: Success })?))
}

fn post_execution(deps: DepsMut, env: Env, msg: PostExecutionMsg) -> StdResult<Response> {
    // load task info and remove task from map
    let task_info = TASK_MAP
        .get(deps.storage, &msg.task)
        .ok_or_else(|| StdError::generic_err("task not found"))?;

    // verify that input hash is correct one for Task
    if msg.input_hash.as_slice() != task_info.input_hash.to_vec() {
        return Err(StdError::generic_err("input hash does not match task"));
    }

    let result = match base64::decode(msg.result) {
        Ok(bytes) => bytes,
        Err(_) => {return Err(StdError::generic_err("could not decode base64 result string"));}
    };

    // rename for clarity (original source network is now the routing destination)
    let routing_info = task_info.source_network;

    // "hasher" is used to perform multiple Keccak256 hashes
    let mut hasher = Keccak256::new();

    // create hash of entire packet (used to verify the message wasn't modified in transit)
    let data = [
        env.block.chain_id.as_bytes(),           // source network
        routing_info.as_bytes(),                 // task_destination_network
        msg.task.task_id.as_bytes(),             // task ID
        task_info.payload_hash.as_slice(),       // original payload message
        result.as_slice(),                       // result
        task_info.callback_address.as_slice(),   // callback address
        task_info.callback_selector.as_slice(),  // callback selector
    ]
    .concat();
    hasher.update(&data);
    let packet_hash = hasher.finalize();

    // load this gateway's signing key
    let private_key = CONFIG.load(deps.storage)?.signing_keys.sk;
    println!("{:?}", private_key);

    // NOTE: api.secp256k1_sign() will perform an additional sha_256 hash operation on the given data
    let packet_signature = {
        deps.api
            .secp256k1_sign(&packet_hash, &private_key.as_slice())
            .map_err(|err| StdError::generic_err(err.to_string()))?
    };
    println!("{:?}", packet_signature);

    // NOTE: The result_signature and packet_signature are both missing the recovery ID (v = 0 or 1), due to a Ethereum bug (v = 27 or 28).
    // we need to either manually check both recovery IDs (v = 27 && v = 28) in the solidity contract (I've leaved this the hard way.)
    // or we can find out the two recovery IDs inside of this contract here and keep the solidity contract slim (which is probably the better way when it comes to gas costs):

    // Load the original public key from storage
    let public_key_data = CONFIG.load(deps.storage)?.signing_keys.pk;

    // Deserialize the uncompressed public key
    let uncompressed_public_key = PublicKey::parse(&public_key_data).map_err(|err| StdError::generic_err(err.to_string()))?;

    // Compress the public key
    let compressed_public_key = uncompressed_public_key.serialize_compressed();

    // Recover and compare public keys for packet, do v = 0 (= 27 in ethereum) and v = 1 (= 28 in ethereum)
    let packet_public_key_27 = deps.api.secp256k1_recover_pubkey(&sha_256(&packet_hash), &packet_signature, 0)
    .map_err(|err| StdError::generic_err(err.to_string()))?;
    let packet_public_key_28 = deps.api.secp256k1_recover_pubkey(&sha_256(&packet_hash), &packet_signature, 1)
    .map_err(|err| StdError::generic_err(err.to_string()))?;

    let packet_recovery_id = if packet_public_key_27 == compressed_public_key {
        27
    } else if packet_public_key_28 == compressed_public_key {
        28
    }
    else {
        return Err(StdError::generic_err("Generation of Recovery ID for Packet Signature failed"));
    };

    let payload_hash = format!("0x{}",task_info.payload_hash.as_slice().encode_hex::<String>());
    let result = format!("0x{}", result.as_slice().encode_hex::<String>());
    let packet_hash = format!("0x{}", sha_256(&packet_hash).encode_hex::<String>());
    let packet_signature = format!("0x{}{:x}", &packet_signature.encode_hex::<String>(),packet_recovery_id);
    let callback_address = format!("0x{}", task_info.callback_address.as_slice().encode_hex::<String>());
    let callback_selector = format!("0x{}", task_info.callback_selector.as_slice().encode_hex::<String>());
    let callback_gas_limit = format!("0x{}", task_info.callback_gas_limit.to_be_bytes().encode_hex::<String>());

    // task info
    let result_info = ResultInfo {
        source_network: env.block.chain_id,
        task_destination_network: routing_info,
        task_id: msg.task.task_id.clone(),
        payload_hash: payload_hash,
        result: result,
        packet_hash: packet_hash,
        packet_signature: packet_signature,
        callback_address: callback_address,
        callback_selector: callback_selector,
        callback_gas_limit: callback_gas_limit,
    };

    RESULT_MAP.insert(deps.storage, &msg.task, &result_info)?;

    Ok(Response::new()
        .add_attribute_plaintext("source_network", result_info.source_network)
        .add_attribute_plaintext("task_destination_network", result_info.task_destination_network)
        .add_attribute_plaintext("task_id", result_info.task_id)
        .add_attribute_plaintext("payload_hash", result_info.payload_hash)
        .add_attribute_plaintext("result", result_info.result)
        .add_attribute_plaintext("packet_hash", result_info.packet_hash)
        .add_attribute_plaintext("packet_signature", result_info.packet_signature)
        .add_attribute_plaintext("callback_address", result_info.callback_address)
        .add_attribute_plaintext("callback_selector", result_info.callback_selector)
        .add_attribute_plaintext("callback_gas_limit", result_info.callback_gas_limit))
}

#[cfg(feature = "contract")]
/////////////////////////////////////// Query /////////////////////////////////////
/// Returns QueryResult
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `msg` - QueryMsg passed in with the query call
#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    let response = match msg {
        QueryMsg::GetPublicKeys {} => query_public_keys(deps),
        QueryMsg::GetExecutionResult {task} => query_execution_result(deps, task),
    };
    pad_query_result(response, BLOCK_SIZE)
}

fn query_execution_result(deps: Deps, task: Task) -> StdResult<Binary> {

    let task_info = RESULT_MAP
        .get(deps.storage, &task)
        .ok_or_else(|| StdError::generic_err("task not found"))?;

    to_binary(&ResultInfo {
        source_network: task_info.source_network,
        task_destination_network: task_info.task_destination_network,
        task_id: task_info.task_id,
        payload_hash: task_info.payload_hash,
        result: task_info.result,
        packet_hash: task_info.packet_hash,
        packet_signature: task_info.packet_signature,
        callback_address: task_info.callback_address,
        callback_selector: task_info.callback_selector,
        callback_gas_limit: task_info.callback_gas_limit
    })
}

// the encryption key will be a base64 string, the verifying key will be a '0x' prefixed hex string
fn query_public_keys(deps: Deps) -> StdResult<Binary> {
    let state: State = CONFIG.load(deps.storage)?;
    to_binary(&PublicKeyResponse {
        encryption_key: state.encryption_keys.pk,
        verification_key: format!("0x{}",state.signing_keys.pk.as_slice().encode_hex::<String>()),
    })
}

/////////////////////////////////////// Helpers /////////////////////////////////////

/// Returns (PublicKey, StaticSecret, Vec<u8>)
///
/// generates a public and private key pair
///
/// # Arguments
///
/// * `env` - contract's environment to be used for randomization
pub fn generate_keypair(
    env: &Env,
) -> Result<(PrivateKey, PublicKey), StdError> {

    // generate and return key pair
    let mut rng = ContractPrng::from_env(env);
    let sk = PrivateKey::parse(&rng.rand_bytes())?;
    let pk = sk.pubkey();

    Ok((sk, pk))
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{from_binary, Addr, Api, Binary, Empty};

    use chacha20poly1305::aead::{Aead, NewAead};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    use secp256k1::{ecdh::SharedSecret, Message, Secp256k1, SecretKey};

    const OWNER: &str = "admin0001";
    const SOMEBODY: &str = "somebody";

    #[track_caller]
    fn setup_test_case(deps: DepsMut) -> Result<Response, StdError> {
        // Instantiate a contract with entropy
        let admin = Some(Addr::unchecked(OWNER.to_owned()));

        let init_msg = InstantiateMsg { admin };
        instantiate(deps, mock_env(), mock_info(OWNER, &[]), init_msg)
    }

    #[track_caller]
    fn get_gateway_encryption_key(deps: Deps) -> Binary {
        let query_msg = QueryMsg::GetPublicKeys {};
        let query_result = query(deps, mock_env(), query_msg);
        let query_answer: PublicKeyResponse = from_binary(&query_result.unwrap()).unwrap();
        let gateway_pubkey = query_answer.encryption_key;
        gateway_pubkey
    }

    #[track_caller]
    fn get_gateway_verification_key(deps: Deps) -> String {
        let query_msg = QueryMsg::GetPublicKeys {};
        let query_result = query(deps, mock_env(), query_msg);
        let query_answer: PublicKeyResponse = from_binary(&query_result.unwrap()).unwrap();
        let gateway_pubkey = query_answer.verification_key;
        gateway_pubkey
    }

    #[test]
    fn test_init() {
        let mut deps = mock_dependencies();

        let response = setup_test_case(deps.as_mut());
        assert!(response.is_ok());
    }

    #[test]
    fn test_query() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(OWNER, &[]);

        // initialize
        setup_test_case(deps.as_mut()).unwrap();

        // query
        let msg = QueryMsg::GetPublicKeys {};
        let res = query(deps.as_ref(), env.clone(), msg);
        assert!(res.is_ok(), "query failed: {}", res.err().unwrap());
        let value: PublicKeyResponse = from_binary(&res.unwrap()).unwrap();
        assert_eq!(value.encryption_key.as_slice().len(), 33);
    }

    #[test]
    fn test_pre_execution() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(OWNER, &[]);

        // initialize
        setup_test_case(deps.as_mut()).unwrap();

        // get gateway public encryption key
        let gateway_pubkey = get_gateway_encryption_key(deps.as_ref());

        // mock key pair
        let secp = Secp256k1::new();
        let secret_key = Key::from_slice(b"an example very very secret key."); // 32-bytes
        let secret_key = SecretKey::from_slice(secret_key).unwrap();
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

        let wrong_secret_key = Key::from_slice(b"an example very wrong secret key"); // 32-bytes
        let wrong_secret_key = SecretKey::from_slice(wrong_secret_key).unwrap();
        let wrong_public_key = secp256k1::PublicKey::from_secret_key(&secp, &wrong_secret_key);

        // create shared key from user private + gateway public
        let gateway_pubkey = secp256k1::PublicKey::from_slice(gateway_pubkey.as_slice()).unwrap();
        let shared_key = SharedSecret::new(&gateway_pubkey, &secret_key);

        // mock Payload
        let data = "{\"fingerprint\": \"0xF9BA143B95FF6D82\", \"location\": \"Menlo Park, CA\"}"
            .to_string();
        let routing_info =
            Addr::unchecked("secret19zpyd046u4swqpksr3n44cej4j8pg6ahw95y85".to_string());
        let routing_code_hash =
            "2a2fbe493ef25b536bbe0baa3917b51e5ba092e14bd76abf50a59526e2789be3".to_string();
        let user_address = Addr::unchecked("some eth address".to_string());
        let user_key = Binary(public_key.serialize().to_vec());
        let user_pubkey = user_key.clone(); // TODO make this a unique key

        let payload = Payload {
            data: data.clone(),
            routing_info: routing_info.clone(),
            routing_code_hash: routing_code_hash.clone(),
            user_address: user_address.clone(),
            user_key: user_key.clone(),
            callback_address: b"public gateway address".into(),
            callback_selector: b"0xfaef40fe".into(),
            callback_gas_limit: 300_000u32,
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
        let prefix = "\x19Ethereum Signed Message:\n32".as_bytes();
        let mut hasher = Keccak256::new();

        // NOTE: hmmm shouldn't this be a hash of the non-encrypted payload?
        hasher.update(encrypted_payload.as_slice());
        let payload_hash_tmp = hasher.finalize_reset();
        hasher.update([prefix, &payload_hash_tmp].concat());
        let payload_hash = hasher.finalize();

        // let message = Message::from_slice(&payload_hash).unwrap();
        // let payload_signature = secp.sign_ecdsa(&message, &secret_key);

        let payload_signature = deps.api.secp256k1_sign(&payload_hash, secret_key.as_ref()).unwrap();

        // mock wrong payload (encrypted with a key that does not match the one inside the payload)
        let wrong_user_address = Addr::unchecked("wrong eth address".to_string());
        let wrong_user_key = Binary(wrong_public_key.serialize().to_vec());

        let wrong_payload = Payload {
            data: data.clone(),
            routing_info: routing_info.clone(),
            routing_code_hash: routing_code_hash.clone(),
            user_address: wrong_user_address.clone(),
            user_key: wrong_user_key.clone(),
            callback_address: b"public gateway address".into(),
            callback_selector: b"0xfaef40fe".into(),
            callback_gas_limit: 300_000u32,
        };
        let wrong_serialized_payload = to_binary(&wrong_payload).unwrap();

        // encrypt the mock wrong payload
        let wrong_encrypted_payload = cipher
            .encrypt(nonce, wrong_serialized_payload.as_slice())
            .unwrap();

        // test payload user_key does not match given user_key
        let pre_execution_msg = PreExecutionMsg {
            task_id: "1".to_string(),
            source_network: "ethereum".to_string(),
            routing_info: routing_info.clone(),
            routing_code_hash: routing_code_hash.clone(),
            payload: Binary(wrong_encrypted_payload.clone()),
            payload_hash: Binary(payload_hash.to_vec()),
            payload_signature: Binary(payload_signature.to_vec()),
            user_address: user_address.clone(),
            user_key: user_key.clone(),
            user_pubkey: user_pubkey.clone(),
            handle: "test".to_string(),
            nonce: Binary(b"unique nonce".to_vec()),
            callback_gas_limit: 300_000u32,
        };
        let handle_msg = ExecuteMsg::Input {
            inputs: pre_execution_msg,
        };
        let err = execute(deps.as_mut(), env.clone(), info.clone(), handle_msg).unwrap_err();
        assert_eq!(err, StdError::generic_err("verification key mismatch"));

        // wrong routing info
        let wrong_routing_info =
            Addr::unchecked("secret13rcx3p8pxf0ttuvxk6czwu73sdccfz4w6e27fd".to_string());
        let routing_code_hash =
            "19438bf0cdf555c6472fb092eae52379c499681b36e47a2ef1c70f5269c8f02f".to_string();

        // test internal routing info does not match
        let pre_execution_msg = PreExecutionMsg {
            task_id: "1".to_string(),
            source_network: "ethereum".to_string(),
            routing_info: wrong_routing_info.clone(),
            routing_code_hash: routing_code_hash.clone(),
            payload: Binary(encrypted_payload.clone()),
            payload_hash: Binary(payload_hash.to_vec()),
            payload_signature: Binary(payload_signature.to_vec()),
            user_address: user_address.clone(),
            user_key: user_key.clone(),
            user_pubkey: user_pubkey.clone(),
            handle: "test".to_string(),
            nonce: Binary(b"unique nonce".to_vec()),
            callback_gas_limit: 300_000u32,
        };
        let handle_msg = ExecuteMsg::Input {
            inputs: pre_execution_msg,
        };
        let err = execute(deps.as_mut(), env.clone(), info.clone(), handle_msg).unwrap_err();
        assert_eq!(err, StdError::generic_err("routing info mismatch"));

        // test proper input handle
        let pre_execution_msg = PreExecutionMsg {
            task_id: "1".to_string(),
            source_network: "ethereum".to_string(),
            routing_info,
            routing_code_hash,
            payload: Binary(encrypted_payload),
            payload_hash: Binary(payload_hash.to_vec()),
            payload_signature: Binary(payload_signature.to_vec()),
            user_address,
            user_key,
            user_pubkey,
            handle: "test".to_string(),
            nonce: Binary(b"unique nonce".to_vec()),
            callback_gas_limit: 300_000u32,
        };
        let handle_msg = ExecuteMsg::Input {
            inputs: pre_execution_msg,
        };
        let handle_result = execute(deps.as_mut(), env.clone(), info, handle_msg);
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
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(SOMEBODY, &[]);
        // initialize
        setup_test_case(deps.as_mut()).unwrap();

        // get gateway public encryption key
        let gateway_pubkey = get_gateway_encryption_key(deps.as_ref());

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
        let routing_info =
            Addr::unchecked("secret19zpyd046u4swqpksr3n44cej4j8pg6ahw95y85".to_string());
        let routing_code_hash =
            "2a2fbe493ef25b536bbe0baa3917b51e5ba092e14bd76abf50a59526e2789be3".to_string();
        let user_address = Addr::unchecked("some eth address".to_string());
        let user_key = Binary(public_key.serialize().to_vec());
        let user_pubkey = user_key.clone(); // TODO make this a unique key

        let payload = Payload {
            data: data.clone(),
            routing_info: routing_info.clone(),
            routing_code_hash: routing_code_hash.clone(),
            user_address: user_address.clone(),
            user_key: user_key.clone(),
            callback_address: b"public gateway address".into(),
            callback_selector: b"0xfaef40fe".into(),
            callback_gas_limit: 300_000u32,
        };
        let serialized_payload = to_binary(&payload).unwrap();

        // encrypt the payload
        let cipher = ChaCha20Poly1305::new_from_slice(shared_key.as_ref())
            .map_err(|_err| StdError::generic_err("could not create cipher".to_string()))
            .unwrap();
        let nonce = Nonce::from_slice(b"unique nonce"); // 12-bytes; unique per message
        let encrypted_payload = cipher
            .encrypt(nonce, serialized_payload.as_slice())
            .expect("encryption failure!");

        // sign the payload
        let prefix = "\x19Ethereum Signed Message:\n32".as_bytes();
        let mut hasher = Keccak256::new();

        // NOTE: shouldn't this be a hash of the non-encrypted payload?
        hasher.update(encrypted_payload.as_slice());
        let payload_hash_tmp = hasher.finalize_reset();
        hasher.update([prefix, &payload_hash_tmp].concat());
        let payload_hash = hasher.finalize();

        let payload_signature = deps.api.secp256k1_sign(&payload_hash, secret_key.as_ref()).unwrap();

        // execute input handle
        let pre_execution_msg = PreExecutionMsg {
            task_id: "1".to_string(),
            source_network: "ethereum".to_string(),
            routing_info,
            routing_code_hash,
            payload: Binary(encrypted_payload),
            payload_hash: Binary(payload_hash.to_vec()),
            payload_signature: Binary(payload_signature.to_vec()),
            user_address,
            user_key,
            user_pubkey: user_pubkey.clone(),
            handle: "test".to_string(),
            nonce: Binary(b"unique nonce".to_vec()),
            callback_gas_limit: 300_000u32,
        };
        let handle_msg = ExecuteMsg::Input {
            inputs: pre_execution_msg.clone(),
        };
        execute(deps.as_mut(), env.clone(), info.clone(), handle_msg).unwrap();

        // test incorrect input_hash
        let wrong_post_execution_msg = PostExecutionMsg {
            result: base64::encode("{\"answer\": 42}".to_string()),
            task: Task { network: "ethereum".to_string(), task_id: "1".to_string() },
            input_hash: Binary(sha_256("wrong data".as_bytes()).to_vec()),
        };
        let handle_msg = ExecuteMsg::Output {
            outputs: wrong_post_execution_msg,
        };
        let err = execute(deps.as_mut(), env.clone(), info.clone(), handle_msg).unwrap_err();
        assert_eq!(err, StdError::generic_err("input hash does not match task"));

        // test output handle
        let post_execution_msg = PostExecutionMsg {
            result: base64::encode("{\"answer\": 42}".to_string()),
            task: Task { network: "ethereum".to_string(), task_id: "1".to_string() },
            input_hash: Binary(
                sha_256(&[data.as_bytes(), "1".to_string().as_bytes(), &[0u8]].concat()).to_vec(),
            ),
        };

        let handle_msg = ExecuteMsg::Output {
            outputs: post_execution_msg,
        };
        let handle_result = execute(deps.as_mut(), env.clone(), info.clone(), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle failed: {}",
            handle_result.err().unwrap()
        );
        let logs = handle_result.unwrap().attributes;

        let gateway_pubkey = get_gateway_verification_key(deps.as_ref());
        println!("Gateway public key: {:?}", gateway_pubkey);

        for log in logs.clone() {
            println!("{:?}, {:?}", log.key, log.value)
        }

        assert_eq!(logs[0].value, "secret".to_string());
        assert_eq!(logs[1].value, "ethereum".to_string());
        assert_eq!(logs[2].value, "1".to_string());
        assert_eq!(
            hex::decode(logs[3].value.clone().strip_prefix("0x").unwrap())
                .unwrap()
                .len(),
            32
        );
        assert_eq!(logs[4].value, "0x7b22616e73776572223a2034327d".to_string());

        assert_eq!(
            hex::decode(logs[5].value.clone().strip_prefix("0x").unwrap())
                .unwrap()
                .len(),
            32
        );
        assert_eq!(
            hex::decode(logs[6].value.clone().strip_prefix("0x").unwrap())
                .unwrap()
                .len(),
            65
        );
        assert_eq!(
            hex::decode(logs[7].value.clone().strip_prefix("0x").unwrap())
                .unwrap()
                .len(),
            32
        );
        assert_eq!(
            hex::decode(logs[8].value.clone().strip_prefix("0x").unwrap())
                .unwrap()
                .len(),
            65
        );
    }
}
