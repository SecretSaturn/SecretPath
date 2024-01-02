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
    bytes32(_taskId),
    bytes32(_info.payload_hash),
    bytes(_info.result),
    bytes32(_info.result_hash),
    bytes(_info.result_signature[:64]), //we need to remove the last RecoveryID byte (65 bytes -> 64 bytes) because this wasn't included in the original signature (we added it later on)
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

    (bool val, ) = address(_info.callback_address).call{gas: uint32(_info.callback_gas_limit)}(
        abi.encodeWithSelector(_info.callback_selector, _taskId, _info.result)
    );
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
