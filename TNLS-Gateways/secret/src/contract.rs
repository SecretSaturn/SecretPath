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
    state::{KeyPair, State, TaskInfo, CONFIG, CREATOR, MY_ADDRESS, TASK_MAP},
    PrivContractHandleMsg,
};
use crate::types::Payload;

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
        tx_cnt: 0,
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
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> StdResult<Response> {
    match msg {
        ExecuteMsg::Input { inputs } => {
            pad_handle_result(pre_execution(deps, env, inputs), BLOCK_SIZE)
        }
        ExecuteMsg::Output { outputs } => post_execution(deps, env, outputs),
    }
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
    // verify that signature is correct
    msg.verify(&deps)?;

    // load config
    let config = CONFIG.load(deps.storage)?;

    // decrypt payload
    let payload: Payload = from_binary(&Binary::from(msg.payload.as_slice()))?;
    let input_values = payload.data;

    // combine input values and task ID to create verification hash
    let input_hash = sha_256(&[input_values.as_bytes(), &msg.task_id.to_be_bytes()].concat());

    // verify the internal verification key matches the user address
    if payload.user_key != msg.user_key {
        return Err(StdError::generic_err("verification key mismatch"));
    }
    // verify the routing info matches the internally stored routing info
    if msg.routing_info != payload.routing_info {
        return Err(StdError::generic_err("routing info mismatch"));
    }

    // create a task information store
    let task_info = TaskInfo {
        payload: msg.payload, // storing the ENCRYPTED payload
        payload_hash: msg.payload_hash,
        input_hash, // storing the DECRYPTED input_values hashed together with task ID
        source_network: msg.source_network,
        user_address: payload.user_address.clone(),
        callback_address: payload.callback_address.clone(),
        callback_selector: payload.callback_selector,
        callback_gas_limit: payload.callback_gas_limit
    };

    // map task ID to task info
    TASK_MAP.insert(deps.storage, &msg.task_id, &task_info)?;

    // load this gateway's signing key
    let mut signing_key_bytes = [0u8; 32];
    signing_key_bytes.copy_from_slice(config.signing_keys.sk.as_slice());

    // used in production to create signature
    #[cfg(target_arch = "wasm32")]
    let signature = deps
        .api
        .secp256k1_sign(&input_hash, &signing_key_bytes)
        .map_err(|err| StdError::generic_err(err.to_string()))?;
    // let signature = PrivateKey::parse(&signing_key_bytes)?
    //     .sign(&input_hash, deps.api)
    //     .serialize()
    //     .to_vec();

    // used only in unit testing to create signatures
    #[cfg(not(target_arch = "wasm32"))]
    let signature = {
        let secp = secp256k1::Secp256k1::signing_only();
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
            user_address: payload.user_address,
            task_id: msg.task_id,
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
        .add_attribute_plaintext("task_id", msg.task_id.to_string())
        .add_attribute_plaintext("status", "sent to private contract")
        .set_data(to_binary(&InputResponse { status: Success })?))
}

fn post_execution(deps: DepsMut, _env: Env, msg: PostExecutionMsg) -> StdResult<Response> {
    // load task info and remove task ID from map
    let task_info = TASK_MAP
        .get(deps.storage, &msg.task_id)
        .ok_or_else(|| StdError::generic_err("task id not found"))?;

    // this panics in unit tests
    #[cfg(target_arch = "wasm32")]
    TASK_MAP.remove(deps.storage, &msg.task_id)?;

    // verify that input hash is correct one for Task ID
    if msg.input_hash.as_slice() != task_info.input_hash.to_vec() {
        return Err(StdError::generic_err("input hash does not match task id"));
    }

    // rename for clarity (original source network is now the routing destination)
    let routing_info = task_info.source_network;

    // "hasher" is used to perform multiple Keccak256 hashes
    let mut hasher = Keccak256::new();

    //create message hash of (result + payload + inputs)
    let data = [
         msg.result.as_bytes(),
         task_info.payload.as_slice(),
         &task_info.input_hash,
    ]
    .concat();
    hasher.update(&data);
    let result_hash = hasher.finalize_reset();

    // load this gateway's signing key
    let private_key = CONFIG.load(deps.storage)?.signing_keys.sk;
    let mut signing_key_bytes = [0u8; 32];
    signing_key_bytes.copy_from_slice(private_key.as_slice());

    // used in production to create signatures
    // NOTE: api.secp256k1_sign() will perform an additional sha_256 hash operation on the given data
    #[cfg(target_arch = "wasm32")]
    let result_signature = {
        // let sk = PrivateKey::parse(&signing_key_bytes)?;
        // let result_signature = sk.sign(&result_hash, deps.api).serialize().to_vec();

        let result_signature = deps
            .api
            .secp256k1_sign(&result_hash, &signing_key_bytes)
            .map_err(|err| StdError::generic_err(err.to_string()))?;

        result_signature
    };

    // used only in unit testing to create signatures
    #[cfg(not(target_arch = "wasm32"))]
    let result_signature = {
        let secp = secp256k1::Secp256k1::signing_only();
        let sk = secp256k1::SecretKey::from_slice(&signing_key_bytes).unwrap();

        let result_message = secp256k1::Message::from_slice(&result_hash)
            .map_err(|err| StdError::generic_err(err.to_string()))?;
        let result_signature = secp
            .sign_ecdsa_recoverable(&result_message, &sk)
            .serialize_compact();

        result_signature.1
    };

    
    let mut task_id_padded = [0u8; 32]; // Create a 32-byte array filled with zeros
    // Convert the task_id to an 8-byte big-endian array & Copy the 8-byte big-endian representation to the end of the result array
    task_id_padded[32 - msg.task_id.to_be_bytes().len()..].copy_from_slice(msg.task_id.to_be_bytes().as_slice());

    // create hash of entire packet (used to verify the message wasn't modified in transit)
    let data = [
        "secret".as_bytes(),               // source network
       // routing_info.as_bytes(),           // task_destination_network
        task_id_padded.as_slice(), //msg.task_id.to_be_bytes().as_slice(),        // task ID
        // task_info.payload.as_slice(),      // payload (original encrypted or unencrypted payload)
        task_info.payload_hash.as_slice(), // original payload message
        msg.result.as_bytes(),             // result
        sha_256(&result_hash).as_slice(),                      // result message
        result_signature.as_slice(),                 // result signature
        task_info.callback_address.as_slice(), // callback address
        task_info.callback_selector.as_slice(), // callback selector
    ]
    .concat();
    hasher.update(&data);
    let packet_hash = hasher.finalize();

    // used in production to create signature
    // NOTE: api.secp256k1_sign() will perform an additional sha_256 hash operation on the given data
    #[cfg(target_arch = "wasm32")]
    let packet_signature = {
        deps.api
            .secp256k1_sign(&packet_hash, &signing_key_bytes)
            .map_err(|err| StdError::generic_err(err.to_string()))?
    };
    // let packet_signature = {
    //     PrivateKey::parse(&signing_key_bytes)?
    //         .sign(&packet_hash, deps.api)
    //         .serialize()
    //         .to_vec()
    // };

    // used only in unit testing to create signature
    #[cfg(not(target_arch = "wasm32"))]
    let packet_signature = {
        let secp = secp256k1::Secp256k1::signing_only();
        let sk = secp256k1::SecretKey::from_slice(&signing_key_bytes).unwrap();

        let packet_message = secp256k1::Message::from_slice(&sha_256(&packet_hash))
            .map_err(|err| StdError::generic_err(err.to_string()))?;

        secp.sign_ecdsa(&packet_message, &sk).serialize_compact()
    };

    // convert the hashes and signatures into hex byte strings
    // NOTE: we need to perform the additional sha_256 because that is what the secret network API method does
    // NOTE: The result_signature and packet_signature are both missing the recovery ID (v = 0 or 1), due to a Ethereum bug (v = 27 or 28).
    // we need to either manually check both recovery IDs (v = 27 && v = 28) in the solidity contract. (i've leaved this the hard way.)

    // or we can find out the two recovery IDs inside of this contract here and keep the solidity contract slim (which is probably the better way when it comes to gas costs):

    // Load the original public key from storage
    let public_key_data = CONFIG.load(deps.storage)?.signing_keys.pk;
 
    // Deserialize the uncompressed public key
    let uncompressed_public_key = PublicKey::parse(&public_key_data).map_err(|err| StdError::generic_err(err.to_string()))?;
 
    // Compress the public key
    let compressed_public_key = uncompressed_public_key.serialize_compressed();

    // Recover and compare public keys for result, do v = 0 (= 27 in ethereum) and v = 1 (= 28 in ethereum)
    let result_public_key_27 = {deps.api.secp256k1_recover_pubkey(&sha_256(&result_hash), &result_signature, 0)
    .map_err(|err| StdError::generic_err(err.to_string()))?};
    let result_public_key_28 = {deps.api.secp256k1_recover_pubkey(&sha_256(&result_hash), &result_signature, 1)
    .map_err(|err| StdError::generic_err(err.to_string()))?};

    let result_recovery_id = if result_public_key_27 == compressed_public_key {
        27
    } else if result_public_key_28 == compressed_public_key {
        28
    }
    else {
        return Err(StdError::generic_err("Generation of Recovery ID for Result Signature failed"));
    };

    // Recover and compare public keys for packet, do v = 0 (= 27 in ethereum) and v = 1 (= 28 in ethereum)
    let packet_public_key_27 = {deps.api.secp256k1_recover_pubkey(&sha_256(&packet_hash), &packet_signature, 0)
    .map_err(|err| StdError::generic_err(err.to_string()))?};
    let packet_public_key_28 = {deps.api.secp256k1_recover_pubkey(&sha_256(&packet_hash), &packet_signature, 1)
    .map_err(|err| StdError::generic_err(err.to_string()))?};

    let packet_recovery_id = if packet_public_key_27 == compressed_public_key {
        27
    } else if packet_public_key_28 == compressed_public_key {
        28
    }
    else {
        return Err(StdError::generic_err("Generation of Recovery ID for Packet Signature failed"));
    };

    let payload_hash = format!(
        "0x{}",
        task_info.payload_hash.as_slice().encode_hex::<String>()
    );
    let result = format!("0x{}", msg.result.as_bytes().encode_hex::<String>());
    let result_hash = format!("0x{}", sha_256(&result_hash).encode_hex::<String>());
    let result_signature = format!("0x{}{:x}", &result_signature.encode_hex::<String>(),result_recovery_id);
    let packet_hash = format!("0x{}", sha_256(&packet_hash).encode_hex::<String>());
    let packet_signature = format!("0x{}{:x}", &packet_signature.encode_hex::<String>(),packet_recovery_id);
    let callback_address = format!("0x{}", task_info.callback_address.as_slice().encode_hex::<String>());
    let callback_selector = format!("0x{}", task_info.callback_selector.as_slice().encode_hex::<String>());
    let callback_gas_limit = format!("0x{}", task_info.callback_gas_limit.to_be_bytes().encode_hex::<String>());

    Ok(Response::new()
        .add_attribute_plaintext("source_network", "secret")
        .add_attribute_plaintext("task_destination_network", routing_info)
        .add_attribute_plaintext("task_id", msg.task_id.to_string())
        .add_attribute_plaintext("payload_hash", payload_hash)
        .add_attribute_plaintext("result", result)
        .add_attribute_plaintext("result_hash", result_hash)
        .add_attribute_plaintext("result_signature", result_signature)
        .add_attribute_plaintext("packet_hash", packet_hash)
        .add_attribute_plaintext("packet_signature", packet_signature)
        .add_attribute_plaintext("callback_address", callback_address)
        .add_attribute_plaintext("callback_selector", callback_selector)
        .add_attribute_plaintext("callback_gas_limit", callback_gas_limit))
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
    };
    pad_query_result(response, BLOCK_SIZE)
}

// the encryption key will be a base64 string, the verifying key will be a '0x' prefixed hex string
fn query_public_keys(deps: Deps) -> StdResult<Binary> {
    let state: State = CONFIG.load(deps.storage)?;
    to_binary(&PublicKeyResponse {
        encryption_key: state.encryption_keys.pk,
        verification_key: format!(
            "0x{}",
            state.signing_keys.pk.as_slice().encode_hex::<String>()
        ),
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
    use cosmwasm_std::{from_binary, Addr, Binary, Empty};

    use chacha20poly1305::aead::{Aead, NewAead};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    use secp256k1::{ecdh::SharedSecret, Message, Secp256k1, SecretKey};

    const OWNER: &str = "admin0001";
    const SOMEBODY: &str = "somebody";

    #[track_caller]
    fn setup_test_case(deps: DepsMut) -> Result<Response<Empty>, StdError> {
        // Instantiate a contract with entropy
        let admin = Some(Addr::unchecked(OWNER.to_owned()));

        let init_msg = InstantiateMsg {
            admin,
        };
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

        let response = setup_test_case(deps.as_mut()).unwrap();
        assert_eq!(1, response.messages.len());
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

        // mock wrong payload (encrypted with a key that does not match the one inside the payload)
        let wrong_user_address = Addr::unchecked("wrong eth address".to_string());
        let wrong_user_key = Binary(wrong_public_key.serialize().to_vec());

        let wrong_payload = Payload {
            data: data.clone(),
            routing_info: routing_info.clone(),
            routing_code_hash: routing_code_hash.clone(),
            user_address: wrong_user_address.clone(),
            user_key: wrong_user_key.clone(),
        };
        let wrong_serialized_payload = to_binary(&wrong_payload).unwrap();

        // encrypt the mock wrong payload
        let wrong_encrypted_payload = cipher
            .encrypt(nonce, wrong_serialized_payload.as_slice())
            .unwrap();

        // test payload user_key does not match given user_key
        let pre_execution_msg = PreExecutionMsg {
            task_id: 1,
            handle: "test".to_string(),
            routing_info: routing_info.clone(),
            routing_code_hash: routing_code_hash.clone(),
            user_address: user_address.clone(),
            user_key: user_key.clone(),
            user_pubkey: user_pubkey.clone(),
            payload: Binary(wrong_encrypted_payload.clone()),
            nonce: Binary(b"unique nonce".to_vec()),
            payload_hash: Binary(payload_hash.to_vec()),
            payload_signature: Binary(payload_signature.serialize_compact().to_vec()),
            source_network: "ethereum".to_string(),
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
            task_id: 1u64,
            source_network: "ethereum".to_string(),
            routing_info: wrong_routing_info.clone(),
            routing_code_hash: routing_code_hash.clone(),
            payload: Binary(encrypted_payload.clone()),
            payload_hash: Binary(payload_hash.to_vec()),
            payload_signature: Binary(payload_signature.serialize_compact().to_vec()),
            user_address: user_address.clone(),
            user_key: user_key.clone(),
            user_pubkey: user_pubkey.clone(),
            handle: "test".to_string(),
            nonce: Binary(b"unique nonce".to_vec()),
        };
        let handle_msg = ExecuteMsg::Input {
            inputs: pre_execution_msg,
        };
        let err = execute(deps.as_mut(), env.clone(), info.clone(), handle_msg).unwrap_err();
        assert_eq!(err, StdError::generic_err("routing info mismatch"));

        // test proper input handle
        let pre_execution_msg = PreExecutionMsg {
            task_id: 1u64,
            handle: "test".to_string(),
            routing_info,
            routing_code_hash,
            user_address,
            user_key,
            user_pubkey,
            payload: Binary(encrypted_payload),
            nonce: Binary(b"unique nonce".to_vec()),
            payload_hash: Binary(payload_hash.to_vec()),
            payload_signature: Binary(payload_signature.serialize_compact().to_vec()),
            source_network: "ethereum".to_string(),
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
            task_id: 1u64,
            source_network: "ethereum".to_string(),
            routing_info,
            routing_code_hash,
            payload: Binary(encrypted_payload),
            payload_hash: Binary(payload_hash.to_vec()),
            payload_signature: Binary(payload_signature.serialize_compact().to_vec()),
            user_address,
            user_key,
            user_pubkey: user_pubkey.clone(),
            handle: "test".to_string(),
            nonce: Binary(b"unique nonce".to_vec()),
        };
        let handle_msg = ExecuteMsg::Input {
            inputs: pre_execution_msg.clone(),
        };
        execute(deps.as_mut(), env.clone(), info.clone(), handle_msg).unwrap();

        // test incorrect input_hash
        let wrong_post_execution_msg = PostExecutionMsg {
            result: "{\"answer\": 42}".to_string(),
            task_id: 1u64,
            input_hash: Binary(sha_256("wrong data".as_bytes()).to_vec()),
        };
        let handle_msg = ExecuteMsg::Output {
            outputs: wrong_post_execution_msg,
        };
        let err = execute(deps.as_mut(), env.clone(), info.clone(), handle_msg).unwrap_err();
        assert_eq!(
            err,
            StdError::generic_err("input hash does not match task id")
        );

        // test output handle
        let post_execution_msg = PostExecutionMsg {
            result: "{\"answer\": 42}".to_string(),
            task_id: 1,
            input_hash: Binary(
                sha_256(&[data.as_bytes(), 1u64.to_le_bytes().as_ref()].concat()).to_vec(),
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
