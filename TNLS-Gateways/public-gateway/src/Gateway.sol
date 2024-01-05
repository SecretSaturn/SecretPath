// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

contract Gateway {

    /*//////////////////////////////////////////////////////////////
                              Structs
    //////////////////////////////////////////////////////////////*/

    struct ReducedTask {
        bytes31 payload_hash_reduced;
        bool completed;
    }

    struct ExecutionInfo {
        bytes user_key;
        bytes user_pubkey;
        string routing_code_hash;
        string handle;
        bytes12 nonce;
        bytes payload;
        bytes payload_signature;
    }

    struct PostExecutionInfo {
        bytes32 payload_hash;
        bytes32 result_hash;
        bytes32 packet_hash;
        bytes20 callback_address;
        bytes4 callback_selector;
        bytes4 callback_gas_limit;
        bytes packet_signature;
        bytes result_signature;
        bytes result;
    }

    /*//////////////////////////////////////////////////////////////
                              Errors
    //////////////////////////////////////////////////////////////*/

    /// @notice thrown when the signature s is invalid
    error InvalidSignatureSValue();

    /// @notice thrown when the signature length is invalid
    error InvalidSignatureLength();

    /// @notice thrown when the signature is invalid
    error InvalidSignature();

    /// @notice Thrown when the recovered ResultHash or ResultSignature is invalid
    error InvalidResultSignature();

    /// @notice thrown when the PacketSignature is invalid
    error InvalidPacketSignature();

    /// @notice thrown when the PayloadHash is invalid
    error InvalidPayloadHash();

    /// @notice thrown when the Task was already completed
    error TaskAlreadyCompleted();

    /// @notice thrown when the Callback failed
    error CallbackError();

    /*//////////////////////////////////////////////////////////////
                              Helpers
    //////////////////////////////////////////////////////////////*/

    /// @notice Splitting signature util for recovery
    /// @param _sig The signature
    function splitSignature(bytes memory _sig) private pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(_sig.length == 65, "invalid signature length");

        assembly {
            // first 32 bytes, after the length prefix
            r := mload(add(_sig, 32))
            // second 32 bytes
            s := mload(add(_sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(_sig, 96)))
        }
    }

    /// @notice Recover the signer from message hash with a valid recovery ID
    /// @param _signedMessageHash the signed message hash 
    /// @param _signature The signature that needs to be verified

    function recoverSigner(bytes32 _signedMessageHash, bytes memory _signature) private pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);

        return ecrecover(_signedMessageHash, v, r, s);
    }

    /// @notice Get the encoded hash of the inputs for signing
    /// @param _routeInput Route name
    /// @param _verificationAddressInput Address corresponding to the route
    function getRouteHash(string calldata _routeInput, address _verificationAddressInput) private pure returns (bytes32) {
        return keccak256(abi.encode(_routeInput, _verificationAddressInput));
    }

    function sliceLastByte(bytes32 data) private pure returns (bytes31) {
        return bytes31(data & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00);
    }

    /*//////////////////////////////////////////////////////////////
                              Events
    //////////////////////////////////////////////////////////////*/

    event logNewTask(
        uint256 indexed task_id,
        string source_network,
        address user_address,
        string routing_info,
        bytes32 payload_hash,
        ExecutionInfo info
    );

    event logCompletedTask(uint256 indexed task_id, bytes32 payload_hash, bytes32 result_hash);

    /// @notice Emitted when we recieve callback for our result of the computation
    event ComputedResult(uint256 taskId, bytes result);

    /*//////////////////////////////////////////////////////////////
                             Constructor
    //////////////////////////////////////////////////////////////*/

    address private immutable owner;
    string private chainIdentifier;
    string private routing_info;
    string private routing_code_hash;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "UNAUTHORIZED");
        _;
    }

    /*//////////////////////////////////////////////////////////////
                             Initialization
    //////////////////////////////////////////////////////////////*/

    address private masterVerificationAddress;

    /// @notice Initialize the verification address
    /// @param _masterVerificationAddress The input address
    function setMasterVerificationAddress(address _masterVerificationAddress) external onlyOwner {
        masterVerificationAddress = _masterVerificationAddress;
    }

    function setContractAddressAndCodeHash(string calldata _contractAddress, string calldata _codeHash) external onlyOwner {
        routing_info = _contractAddress;
        routing_code_hash = _codeHash;
    }

    function setChainidentifier(string calldata _chainIdentifier) external onlyOwner {
        chainIdentifier = _chainIdentifier;
    }

    /*//////////////////////////////////////////////////////////////
                             Update Routes
    //////////////////////////////////////////////////////////////*/

    /// @dev mapping of chain name string to the verification address
    mapping(string => address) private route;

    /// @notice Updating the route
    /// @param _route Route name
    /// @param _verificationAddress Address corresponding to the route
    /// @param _signature Signed hashed inputs(_route + _verificationAddress)
    function updateRoute(string calldata _route, address _verificationAddress, bytes calldata _signature) external onlyOwner {
        bytes32 routeHash = getRouteHash(_route, _verificationAddress);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", routeHash));

        if (recoverSigner(ethSignedMessageHash, _signature) != masterVerificationAddress) {
            revert InvalidSignature();
        }

        route[_route] = _verificationAddress;
    }

    /*//////////////////////////////////////////////////////////////
                             Pre Execution
    //////////////////////////////////////////////////////////////*/

    uint256 private taskId = 1;

    /// @dev Task ID ====> Task
    mapping(uint256 => ReducedTask) private tasks;

    /// @notice Send
    /// @param _userAddress  User address
    /// @param _sourceNetwork Source network of msg
    /// @param _routingInfo Routing info for computation
    /// @param _payloadHash Payload hash
    /// @param _info ExecutionInfo struct

    function send(        
        bytes32 _payloadHash,
        address _userAddress,
        string calldata _sourceNetwork,
        string calldata _routingInfo,
        ExecutionInfo calldata _info) 
        external {

        // Payload hash signature verification

        if (recoverSigner(_payloadHash, _info.payload_signature) != _userAddress) {
            revert InvalidSignature();
        }

        // persisting the task
        tasks[taskId] = ReducedTask(sliceLastByte(_payloadHash), false);

        emit logNewTask(
            taskId,
            _sourceNetwork,
            _userAddress,
            _routingInfo,
            _payloadHash,
            _info
        );

	    taskId++;
    }

    function requestRandomWords(
        uint32 _numWords,
        uint32 _callbackGasLimit
    ) external payable returns (uint256 requestId) {

        require(_numWords <= 50, "Too many words requested");

        string memory callback_address = Encoders.encodeBase64(abi.encodePacked(msg.sender));

        bytes memory payload = abi.encodePacked(
            bytes23(0x7b2264617461223a227b5c226e756d576f7264735c223a), //bytes representation of '{"data":"{\"numWords\":' because solidity has problems with correct string escaping of numWords
            Encoders.uint256toString(_numWords),
            '}","routing_info": "',routing_info,
            '","routing_code_hash": "',routing_code_hash,
            '","user_address": "0x0000000000000000000000000000000000000000",', //unused user_address here
            '"user_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",', // 33 bytes of zeros in base64
            '"callback_address": "', callback_address,
            '","callback_selector": "OLpGFA==",', // 0x38ba4614 hex value already converted into base64, callback_selector of the fullfillRandomWords function
            '"callback_gas_limit": ', Encoders.uint256toString(_callbackGasLimit),'}' // Corrected function call
        );

        bytes32 payloadHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32",keccak256(payload)));

        // ExecutionInfo struct
        ExecutionInfo memory executionInfo = ExecutionInfo({
            user_key: new bytes(33), // equals AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA in base64
            user_pubkey: new bytes(64), // Fill with 0 bytes
            routing_code_hash: routing_code_hash,
            handle: "request_random",
            nonce: bytes12(0),
            payload: payload, // Make sure payload is correctly formatted
            payload_signature: new bytes(64) // empty signature, fill with 0 bytes
        });

        // persisting the task
        tasks[taskId] = ReducedTask(sliceLastByte(payloadHash), false);

        emit logNewTask(
            taskId,
            chainIdentifier,
            msg.sender,
            routing_info,
            payloadHash,
            executionInfo
        );
        uint256 oldTaskId = taskId;
        taskId++;
        return oldTaskId;
    }

    /*//////////////////////////////////////////////////////////////
                             Post Execution
    //////////////////////////////////////////////////////////////*/

    /// @notice Post-Execution
    /// @param _taskId Task Id of the executed message
    /// @param _sourceNetwork Source network of the message
    /// @param _info PostExecutionInfo struct

    function postExecution(uint256 _taskId, string calldata _sourceNetwork, PostExecutionInfo calldata _info) external {
    
    ReducedTask storage task = tasks[_taskId];

    // Check if the task is already completed
    if (task.completed) {
        revert TaskAlreadyCompleted();
    }

    if (sliceLastByte(_info.payload_hash) != task.payload_hash_reduced) {
        revert InvalidPayloadHash();
    }

    address checkerAddress = route[_sourceNetwork];

    // Result signature verification
    if (recoverSigner(_info.result_hash, _info.result_signature) != checkerAddress) {
        revert InvalidResultSignature();
    }

    // Concatenate data elements
    bytes memory data =  bytes.concat(
    bytes(_sourceNetwork),
    bytes(chainIdentifier),
    bytes32(_taskId),
    bytes32(_info.payload_hash),
    bytes(_info.result),
    bytes32(_info.result_hash),
    bytes20(_info.callback_address),
    bytes4(_info.callback_selector));
    
    // Perform Keccak256 + sha256 hash
    bytes32 packetHash = sha256(abi.encodePacked(keccak256(data)));

    // Packet signature verification
    if ((_info.packet_hash != packetHash) || recoverSigner(_info.packet_hash, _info.packet_signature) != checkerAddress) {
        revert InvalidPacketSignature();
    }
    
    task.completed = true;

    emit logCompletedTask(_taskId, _info.payload_hash, _info.result_hash);

    // Continue with the function execution

    // Additional conversion for Secret VRF into uint256[] if callback_selector matches the fullfillRandomWords selector.

    bool val; 

    if (_info.callback_selector == bytes4(0x38ba4614)) {
        uint256[] memory randomWords = Encoders.bytesToUint256Array(_info.result);
        (val, ) = address(_info.callback_address).call{gas: uint32(_info.callback_gas_limit)}(
            abi.encodeWithSelector(_info.callback_selector, _taskId, randomWords)
        );
    }
    else {
        (val, ) = address(_info.callback_address).call{gas: uint32(_info.callback_gas_limit)}(
            abi.encodeWithSelector(_info.callback_selector, _taskId, _info.result)
        );
    }
    if (!val) {
        revert CallbackError();
    }
}

    /*//////////////////////////////////////////////////////////////
                               Callback
    //////////////////////////////////////////////////////////////*/

    /// @param _taskId  Task Id of the computation
    /// @param _result  Privately computed result
    function callback(uint256 _taskId, bytes calldata _result) external {
        emit ComputedResult(_taskId, _result);
    }
}

library Encoders {

    function encodeBase64(bytes memory data) internal pure returns (string memory) {
        if (data.length == 0) return "";
        string memory table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        string memory result = new string(4 * ((data.length + 2) / 3));
        /// @solidity memory-safe-assembly
        assembly {
            let tablePtr := add(table, 1)
            let resultPtr := add(result, 32)
            for {
                let dataPtr := data
                let endPtr := add(data, mload(data))
            } lt(dataPtr, endPtr) {
            } {
                dataPtr := add(dataPtr, 3)
                let input := mload(dataPtr)
                mstore8(resultPtr, mload(add(tablePtr, and(shr(18, input), 0x3F))))
                resultPtr := add(resultPtr, 1)
                mstore8(resultPtr, mload(add(tablePtr, and(shr(12, input), 0x3F))))
                resultPtr := add(resultPtr, 1)
                mstore8(resultPtr, mload(add(tablePtr, and(shr(6, input), 0x3F))))
                resultPtr := add(resultPtr, 1)
                mstore8(resultPtr, mload(add(tablePtr, and(input, 0x3F))))
                resultPtr := add(resultPtr, 1)
            }
            switch mod(mload(data), 3)
            case 1 {
                mstore8(sub(resultPtr, 1), 0x3d)
                mstore8(sub(resultPtr, 2), 0x3d)
            }
            case 2 {
                mstore8(sub(resultPtr, 1), 0x3d)
            }
        }
        return result;
    }

   function uint256toString(uint256 value) external pure returns (string memory ptr) {
        assembly {
            ptr := add(mload(0x40), 128)
            mstore(0x40, ptr)
            let end := ptr
            for { 
                let temp := value
                ptr := sub(ptr, 1)
                mstore8(ptr, add(48, mod(temp, 10)))
                temp := div(temp, 10)
            } temp { 
                temp := div(temp, 10)
            } { 
                ptr := sub(ptr, 1)
                mstore8(ptr, add(48, mod(temp, 10)))
            }
            let length := sub(end, ptr)
            ptr := sub(ptr, 32)
            mstore(ptr, length)
        }
    }
    
    function bytesToUint256Array(bytes memory data) internal pure returns (uint256[] memory) {
        require(data.length % 32 == 0, "Data length must be a multiple of 32 bytes");
        uint256[] memory uintArray = new uint256[](data.length / 32);
        uint256 dataLength = data.length;
        assembly {
            let dataPtr := add(data, 0x20) 
            let uintArrayPtr := add(uintArray, 0x20) 
            for { let i := 0 } lt(i, dataLength) { i := add(i, 32) } {
                mstore(add(uintArrayPtr, i), mload(add(dataPtr, i)))
            }
        }
        return uintArray;
    }
}