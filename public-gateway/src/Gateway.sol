// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

contract Gateway {

    struct Task {
        address callback_address;
        bytes4 callback_selector;
        address user_address;
        string source_network;
        string routing_info;
        bytes32 payload_hash;
        bool completed;
    }

    struct ReducedTask {
        bytes32 payload_hash;
        address callback_address;
        bytes4 callback_selector;
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

    /// @notice Splitting signature util for recovery
    /// @param _sig The signature
    function splitSignature(bytes memory _sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(_sig.length == 65, "invalid signature length");

        assembly {
            /*
            First 32 bytes stores the length of the signature

            add(sig, 32) = pointer of sig + 32
            effectively, skips first 32 bytes of signature

            mload(p) loads next 32 bytes starting at the memory address p into memory
            */

            // first 32 bytes, after the length prefix
            r := mload(add(_sig, 32))
            // second 32 bytes
            s := mload(add(_sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(_sig, 96)))
        }

        // implicitly return (r, s, v)
    }

    /// @notice Recover the signer from message hash
    /// @param _ethSignedMessageHash The message hash from getEthSignedMessageHash()
    /// @param _signature The signature that needs to be verified

    function modifiedRecoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature) internal pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);

        if (v < 27) {
            v += 27;
        }
        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

     /// @notice Hashes the encoded message hash
    /// @param _messageHash the message hash
    function getEthSignedMessageHash(bytes32 _messageHash) internal pure returns (bytes32) {
        /*
        Signature is produced by signing a keccak256 hash with the following format:
        "\x19Ethereum Signed Message\n" + len(msg) + msg
        */
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash));
    }

    /// @notice Get the encoded hash of the inputs for signing
    /// @param _routeInput Route name
    /// @param _verificationAddressInput Address corresponding to the route
    function getRouteHash(string memory _routeInput, address _verificationAddressInput) internal pure returns (bytes32) {
        return keccak256(abi.encode(_routeInput, _verificationAddressInput));
    }

    /// @notice thrown when the signature is invalid
    error InvalidSignature();

    /// @notice thrown when the ResultSignature is invalid
    error InvalidResultSignature();

    /// @notice thrown when the PacketSignature is invalid
    error InvalidPacketSignature();

    /// @notice thrown when the PayloadHash is invalid
    error InvalidPayloadHash();

    /// @notice thrown when the Task was already completed
    error TaskAlreadyCompleted();

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
    function initialize(address _masterVerificationAddress) public onlyOwner {
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
    function updateRoute(string memory _route, address _verificationAddress, bytes memory _signature) public onlyOwner {
        bytes32 routeHash = getRouteHash(_route, _verificationAddress);
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(routeHash);

        bool verifySig = modifiedRecoverSigner(ethSignedMessageHash, _signature) == masterVerificationAddress;

        if (!verifySig) {
            revert InvalidSignature();
        }

        route[_route] = _verificationAddress;
    }

    /*//////////////////////////////////////////////////////////////
                             Pre Execution
    //////////////////////////////////////////////////////////////*/

    uint256 public taskId = 1;

    /// @dev Task ID ====> Task
    mapping(uint256 => ReducedTask) public tasks;

    /// @notice Pre-Execution
    /// @param _task Task struct
    /// @param _info ExecutionInfo struct
    function preExecution(Task memory _task, ExecutionInfo memory _info) internal {

        // Payload hash signature verification
        bool verifySig = modifiedRecoverSigner(_task.payload_hash, _info.payload_signature) == _task.user_address;

        if (!verifySig) {
            revert InvalidSignature();
        }

        // persisting the task
        tasks[taskId] = ReducedTask(_task.payload_hash, _task.callback_address, _task.callback_selector, false);

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
    function postExecution(uint256 _taskId, string memory _sourceNetwork, PostExecutionInfo memory _info) public {

        if (tasks[_taskId].completed == true) {
            revert TaskAlreadyCompleted();
        }

        bool verify;
        address recoveredSigner;

        address checkerAddress = route[_sourceNetwork];

        // Payload hash verification from tasks struct
        verify = _info.payload_hash == tasks[_taskId].payload_hash;
        if (!verify) {
            revert InvalidPayloadHash();
        }

        //Packet signature verification
        recoveredSigner = modifiedRecoverSigner(_info.packet_hash, _info.packet_signature);
        verify = recoveredSigner == checkerAddress;
        if (!verify) {
            revert InvalidPacketSignature();
        } 

        // Result signature verification
        recoveredSigner = modifiedRecoverSigner(_info.result_hash, _info.result_signature);
        verify = recoveredSigner == checkerAddress;
        if (!verify) {
            revert InvalidResultSignature();
        }

        (bool val,) = address(tasks[_taskId].callback_address).call(abi.encodeWithSelector(tasks[_taskId].callback_selector, _taskId, _info.result));
        require(val == true, "Callback error");

        tasks[_taskId].completed = true;

        emit logCompletedTask(_taskId, _info.payload_hash, _info.result_hash);
    }

    /// @param _userAddress  User address
    /// @param _sourceNetwork Source network of msg
    /// @param _routingInfo Routing info for computation
    /// @param _payloadHash Payload hash
    /// @param _info ExecutionInfo struct

    function send(
        address _userAddress,
        string memory _sourceNetwork,
        string memory _routingInfo,
        bytes32 _payloadHash,
        ExecutionInfo memory _info
    )
        public
    {

        preExecution(Task(address(this), this.callback.selector, _userAddress, _sourceNetwork, _routingInfo, _payloadHash, false), _info);
    }

    /*//////////////////////////////////////////////////////////////
                               Callback
    //////////////////////////////////////////////////////////////*/

    /// @param _taskId  Task Id of the computation
    /// @param _result  Privately computed result
    function callback(uint256 _taskId, bytes memory _result) external {
        emit ComputedResult(_taskId, _result);
    }
}
