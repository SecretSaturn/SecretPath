// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

contract Gateway {

    /*//////////////////////////////////////////////////////////////
                              Structs
    //////////////////////////////////////////////////////////////*/

    struct Task {
        address callback_address;
        bytes4 callback_selector;
        uint32 callback_gas_limit;
        address user_address;
        bool completed;
        bytes32 payload_hash;
        string source_network;
        string routing_info;
    }

    struct ReducedTask {
        bytes32 payload_hash;
        address callback_address;
        bytes4 callback_selector;
        uint32 callback_gas_limit;
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
        bytes result;
        bytes32 result_hash;
        bytes result_signature;
        bytes32 packet_hash;
        bytes packet_signature;
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

    /// @notice Thrown when the ResultSignature is invalid
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

    /// @notice Recover the signer from message hash with a missing recovery ID
    /// @param _signedMessageHash the signed message hash 
    /// @param _signature The signature that needs to be verified

    function checkSignerForMissingRecoveryID(bytes32 _signedMessageHash, bytes memory _signature, address _checkingAddress) private pure returns (bool) {
        //recover signature

        bytes32 r;
        bytes32 s;

        assembly {
            // first 32 bytes, after the length prefix
            r := mload(add(_signature, 32))
            // second 32 bytes
            s := mload(add(_signature, 64))
        }

        //calculate both ecrecover(_signedMessageHash, v, r, s) for v = 27 and v = 28, casted as uint8

        if (ecrecover(_signedMessageHash, uint8(27), r, s) == _checkingAddress) {
            return true;
        }
        else if (ecrecover(_signedMessageHash, uint8(28), r, s) == _checkingAddress) {
            return true;
        }
        else {
            return false;
        }
    }

    /// @notice Hashes the encoded message hash
    /// @param _messageHash the message hash
    function getEthSignedMessageHash(bytes32 _messageHash) private pure returns (bytes32) {
        /*
        Signature is produced by signing a keccak256 hash with the following format:
        "\x19Ethereum Signed Message\n" + len(msg) + msg
        */
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash));
    }

    /// @notice Get the encoded hash of the inputs for signing
    /// @param _routeInput Route name
    /// @param _verificationAddressInput Address corresponding to the route
    function getRouteHash(string calldata _routeInput, address _verificationAddressInput) private pure returns (bytes32) {
        return keccak256(abi.encode(_routeInput, _verificationAddressInput));
    }

    /*//////////////////////////////////////////////////////////////
                              Events
    //////////////////////////////////////////////////////////////*/

    event logNewTask(
        uint256 indexed task_id,
        string source_network,
        address user_address,
        string routing_info,
        string routing_code_hash,
        bytes payload,
        bytes32 payload_hash,
        bytes payload_signature,
        bytes user_key,
        bytes user_pubkey,
        string handle,
        bytes12 nonce
    );

    event logCompletedTask(uint256 indexed task_id, bytes32 payload_hash, bytes32 result_hash);

    /// @notice Emitted when we recieve callback for our result of the computation
    event ComputedResult(uint256 taskId, bytes result);

    /*//////////////////////////////////////////////////////////////
                             Constructor
    //////////////////////////////////////////////////////////////*/

    address public immutable owner;

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

    address public masterVerificationAddress;

    /// @notice Initialize the verification address
    /// @param _masterVerificationAddress The input address
    function initialize(address _masterVerificationAddress) external onlyOwner {
        masterVerificationAddress = _masterVerificationAddress;
    }

    /*//////////////////////////////////////////////////////////////
                             Update Routes
    //////////////////////////////////////////////////////////////*/

    /// @dev mapping of chain name string to the verification address
    mapping(string => address) public route;

    /// @notice Updating the route
    /// @param _route Route name
    /// @param _verificationAddress Address corresponding to the route
    /// @param _signature Signed hashed inputs(_route + _verificationAddress)
    function updateRoute(string calldata _route, address _verificationAddress, bytes calldata _signature) external onlyOwner {
        bytes32 routeHash = getRouteHash(_route, _verificationAddress);
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(routeHash);

        bool verifySig = recoverSigner(ethSignedMessageHash, _signature) == masterVerificationAddress;

        if (!verifySig) {
            revert InvalidSignature();
        }

        route[_route] = _verificationAddress;
    }

    /*//////////////////////////////////////////////////////////////
                             Pre Execution
    //////////////////////////////////////////////////////////////*/

    uint256 private taskId = 1;

    /// @dev Task ID ====> Task
    mapping(uint256 => ReducedTask) public tasks;

    /// @notice Pre-Execution
    /// @param _task Task struct
    /// @param _info ExecutionInfo struct

    function preExecution(Task memory _task, ExecutionInfo memory _info) private {

        // Payload hash signature verification
        bool verifySig = recoverSigner(_task.payload_hash, _info.payload_signature) == _task.user_address;

        if (!verifySig) {
            revert InvalidSignature();
        }

        // persisting the task
        tasks[taskId] = ReducedTask(_task.payload_hash, _task.callback_address, _task.callback_selector, _task.callback_gas_limit, false);

        emit logNewTask(
            taskId,
            _task.source_network,
            _task.user_address,
            _task.routing_info,
            _info.routing_code_hash,
            _info.payload,
            _task.payload_hash,
            _info.payload_signature,
            _info.user_key,
            _info.user_pubkey,
            _info.handle,
            _info.nonce
            );

	    taskId++;
    }

    /*//////////////////////////////////////////////////////////////
                             Post Execution
    //////////////////////////////////////////////////////////////*/

    /// @notice Post-Execution
    /// @param _taskId Task Id of the executed message
    /// @param _sourceNetwork Source network of the message
    /// @param _info PostExecutionInfo struct

    function postExecution(uint256 _taskId, string calldata _sourceNetwork, PostExecutionInfo calldata _info) external {
    // First, check if the task is already completed
    ReducedTask memory task = tasks[_taskId];

    if (task.completed) {
        revert TaskAlreadyCompleted();
    }

    address checkerAddress = route[_sourceNetwork];

    // Payload hash verification from tasks struct
    if (_info.payload_hash != task.payload_hash) {
        revert InvalidPayloadHash();
    }

    // Result signature verification
    if (checkSignerForMissingRecoveryID(_info.result_hash, _info.result_signature, checkerAddress)) {
        revert InvalidResultSignature();
    }

    // Packet signature verification
    if (checkSignerForMissingRecoveryID(_info.packet_hash, _info.packet_signature, checkerAddress)) {
        revert InvalidPacketSignature();
    }

    task.completed = true;
    task.payload_hash = bytes32(0);
    tasks[_taskId] = task;

    emit logCompletedTask(_taskId, _info.payload_hash, _info.result_hash);

    // Continue with the function execution

    (bool val, ) = address(task.callback_address).call{gas: task.callback_gas_limit}(
        abi.encodeWithSelector(task.callback_selector, _taskId, _info.result)
    );
    if (!val) {
        revert CallbackError();
    }
}

    /// @param _userAddress  User address
    /// @param _sourceNetwork Source network of msg
    /// @param _routingInfo Routing info for computation
    /// @param _payloadHash Payload hash
    /// @param _info ExecutionInfo struct
    /// @param _callbackAddress Callback Address for Post-Execution 
    /// @param _callbackSelector Callback Selector for Post-Execution 
    /// @param _callbackGasLimit Callback Gas Limit for Post-Execution 

    function send(
        address _userAddress,
        string memory _sourceNetwork,
        string memory _routingInfo,
        bytes32 _payloadHash,
        ExecutionInfo memory _info,
        address _callbackAddress, 
        bytes4 _callbackSelector,
        uint32 _callbackGasLimit
    )
        external 
    {
        preExecution(Task(_callbackAddress, _callbackSelector, _callbackGasLimit ,_userAddress, false, _payloadHash, _sourceNetwork, _routingInfo), _info);
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
