// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import "openzeppelin-contracts/contracts/utils/Counters.sol";

library Util {
    /// @notice Structured task for presistence
    /// @param callback_address contract address for callback
    /// @param callback_selector function selector for computed callback
    /// @param user_address The address of the sender
    /// @param source_network Source network of the message
    /// @param routing_info Where to go one pulled into the next gateway
    /// @param payload_hash Payload hash for postExecution verification
    /// @param completed  Task completion status
    struct Task {
        address callback_address;
        bytes4 callback_selector;
        address user_address;
        string source_network;
        string routing_info;
        bytes32 payload_hash;
        bool completed;
    }

    /// @notice Structured task for presistence
    /// @param user_public_key public key bytes
    /// @param handle handle for private contract
    /// @param nonce nonce for private contract
    /// @param routing_info_signature Routing info signature
    /// @param payload Payload for computation
    /// @param payload_signature  hashed payload signature
    /// @param packet_signature  Packet Signature contents mirroring getPacketHash()
    struct ExecutionInfo {
        bytes user_public_key;
        string handle;
        bytes12 nonce;
        bytes routing_info_signature;
        bytes payload;
        bytes payload_signature;
        bytes packet_signature;
    }
}

contract Gateway {
    using Counters for Counters.Counter;

    /// @notice thrown when the signature is invalid
    error InvalidSignature();

    /// @notice thrown when the PayloadHash is invalid
    error InvalidPayloadHash();

    /*//////////////////////////////////////////////////////////////
                              Events
    //////////////////////////////////////////////////////////////*/

    event logNewTask(
        uint256 task_id,
        string source_network,
        string routing_info,
        bytes routing_info_signature,
        bytes payload,
        bytes32 payload_hash,
        bytes payload_signature,
        bytes user_public_key,
        string handle,
        bytes12 nonce,
        bytes packet_signature
    );

    event logCompletedTask(
        string source_network,
        string routing_info,
        bytes routing_info_signature,
        bytes payload,
        bytes32 payload_hash,
        bytes payload_signature,
        bytes result,
        bytes result_signature,
        uint256 task_id
    );

    /*//////////////////////////////////////////////////////////////
                              Task
    //////////////////////////////////////////////////////////////*/

    function newTask(
        address _callbackAddress,
        bytes4 _callbackSelector,
        address _userAddress,
        string memory _sourceNetwork,
        string memory _routingInfo,
        bytes32 _payloadHash
    )
        public
        pure
        returns (Util.Task memory)
    {
        return Util.Task(_callbackAddress, _callbackSelector, _userAddress, _sourceNetwork, _routingInfo, _payloadHash, false);
    }

    /*//////////////////////////////////////////////////////////////
                           Signature Utils
    //////////////////////////////////////////////////////////////*/

    /// @notice Splitting signature util for recovery
    /// @param _sig The signature
    function splitSignature(bytes memory _sig) public pure returns (bytes32 r, bytes32 s, uint8 v) {
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
    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);

        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    /// @notice Hashes the encoded message hash
    /// @param _messageHash the message hash
    function getEthSignedMessageHash(bytes32 _messageHash) public pure returns (bytes32) {
        /*
        Signature is produced by signing a keccak256 hash with the following format:
        "\x19Ethereum Signed Message\n" + len(msg) + msg
        */
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash));
    }

    /*//////////////////////////////////////////////////////////////
                             Constructor
    //////////////////////////////////////////////////////////////*/

    address public owner;

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

        bool verifySig;
        verifySig = recoverSigner(ethSignedMessageHash, _signature) == masterVerificationAddress;

        if (!verifySig) {
            revert InvalidSignature();
        }

        route[_route] = _verificationAddress;
    }

    /// @notice Get the encoded hash of the inputs for signing
    /// @param _routeInput Route name
    /// @param _verificationAddressInput Address corresponding to the route
    function getRouteHash(string memory _routeInput, address _verificationAddressInput) public pure returns (bytes32) {
        return keccak256(abi.encode(_routeInput, _verificationAddressInput));
    }

    /*//////////////////////////////////////////////////////////////
                             Pre Execution
    //////////////////////////////////////////////////////////////*/

    Counters.Counter private taskIds;

    /// @dev Task ID ====> Task
    mapping(uint256 => Util.Task) public tasks;

    /// @notice Pre-Execution
    /// @param _task Task struct
    /// @param _info ExecutionInfo struct
    function preExecution(Util.Task memory _task, Util.ExecutionInfo memory _info) public {
        bytes32 tempHash;
        bytes32 tempSignedEthMessageHash;
        bool verifySig;

        // Route info signature verification
        tempHash = getRouteInfoHash(_task.routing_info);
        tempSignedEthMessageHash = getEthSignedMessageHash(tempHash);
        verifySig = true;
        verifySig = recoverSigner(tempSignedEthMessageHash, _info.routing_info_signature) == _task.user_address;

        if (!verifySig) {
            revert InvalidSignature();
        }

        // Payload hash signature verification
        tempSignedEthMessageHash = getEthSignedMessageHash(_task.payload_hash);
        verifySig = true;
        verifySig = recoverSigner(tempSignedEthMessageHash, _info.payload_signature) == _task.user_address;

        if (!verifySig) {
            revert InvalidSignature();
        }

        // Packet signature verification
        tempHash = getPacketHash(
            _task.callback_address,
            _task.callback_selector,
            _task.user_address,
            _info.user_public_key,
            _info.handle,
            _info.nonce,
            _info.routing_info_signature,
            _info.payload,
            _task.payload_hash,
            _info.payload_signature
        );
        tempSignedEthMessageHash = getEthSignedMessageHash(tempHash);
        verifySig = true;
        verifySig = recoverSigner(tempSignedEthMessageHash, _info.packet_signature) == _task.user_address;
        if (!verifySig) {
            revert InvalidSignature();
        }

        // Incrementing the ID and persisting the task
        taskIds.increment();
        uint256 taskId = taskIds.current();
        tasks[taskId] = _task;

        emit logNewTask(
            taskId,
            _task.source_network,
            _task.routing_info,
            _info.routing_info_signature,
            _info.payload,
            _task.payload_hash,
            _info.payload_signature,
            _info.user_public_key,
            _info.handle,
            _info.nonce,
            _info.packet_signature
            );
    }

    /// @notice Get the encoded hash of the inputs for signing
    /// @param _routingInfo Routing Info
    function getRouteInfoHash(string memory _routingInfo) public pure returns (bytes32) {
        return keccak256(abi.encode(_routingInfo));
    }

    /// @notice Get the encoded hash of the inputs for signing
    /// @param _payload Payload
    function getPayloadHash(bytes memory _payload) public pure returns (bytes32) {
        return keccak256(abi.encode(_payload));
    }

    /// @notice Get the encoded hash of the whole packet
    function getPacketHash(
        address _callbackAddress,
        bytes4 _callbackSelector,
        address _userAddress,
        bytes memory _userPublicKey,
        string memory _handle,
        bytes12 _nonce,
        bytes memory _routingInfoSignature,
        bytes memory _payload,
        bytes32 _payloadHash,
        bytes memory _payloadSignature
    )
        public
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                _callbackAddress,
                _callbackSelector,
                _userAddress,
                _userPublicKey,
                _handle,
                _nonce,
                _routingInfoSignature,
                _payload,
                _payloadHash,
                _payloadSignature
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                             Post Execution
    //////////////////////////////////////////////////////////////*/

    /// @notice Post-Execution
    /// @param _sourceNetwork Source network of the message
    /// @param _routingInfo Where to go one pulled into the next gateway
    /// @param _routingInfoSignature Signed hash of _routingInfo
    /// @param _payload Encrypted (data + routing_info + user_address)
    /// @param _payloadHash hash of _payload
    /// @param _payloadSignature Payload Signature
    /// @param _result Result of the private computation
    /// @param _resultSignature Result Signature
    /// @param _taskId TaskId for the transmission of the message
    function postExecution(
        string memory _sourceNetwork,
        string memory _routingInfo,
        bytes memory _routingInfoSignature,
        bytes memory _payload,
        bytes32 _payloadHash,
        bytes memory _payloadSignature,
        bytes memory _result,
        bytes memory _resultSignature,
        uint256 _taskId
    )
        public
    {
        bytes32 tempHash;
        bytes32 tempSignedEthMessageHash;
        bool verifySig;

        address checkerAddress = route[_sourceNetwork];

        // Route info signature verification
        tempHash = getRouteInfoHash(_routingInfo);
        tempSignedEthMessageHash = getEthSignedMessageHash(tempHash);

        verifySig = true;
        verifySig = recoverSigner(tempSignedEthMessageHash, _routingInfoSignature) == checkerAddress;
        if (!verifySig) {
            revert InvalidSignature();
        }

        // Payload hash signature verification
        verifySig = true;
        verifySig = recoverSigner(_payloadHash, _payloadSignature) == checkerAddress;
        if (!verifySig) {
            revert InvalidSignature();
        }

        // Result signature verification
        tempHash = getResultHash(_result);
        tempSignedEthMessageHash = getEthSignedMessageHash(tempHash);

        verifySig = true;
        verifySig = recoverSigner(tempSignedEthMessageHash, _resultSignature) == checkerAddress;
        if (!verifySig) {
            revert InvalidSignature();
        }

        // Payload hash verification from tasks struct
        bool verifyPayloadHash;
        verifyPayloadHash = _payloadHash == tasks[_taskId].payload_hash;
        if (!verifyPayloadHash) {
            revert InvalidPayloadHash();
        }

        (bool val,) = address(tasks[_taskId].callback_address).call(abi.encodeWithSelector(tasks[_taskId].callback_selector, _result));
        require(val == true, "Callback error");

        tasks[_taskId].completed = true;

        emit logCompletedTask(
            _sourceNetwork, _routingInfo, _routingInfoSignature, _payload, _payloadHash, _payloadSignature, _result, _resultSignature, _taskId
            );
    }

    /// @notice Get the encoded hash of the results for signing
    /// @param _result Results
    function getResultHash(bytes memory _result) public pure returns (bytes32) {
        return keccak256(abi.encode(_result));
    }
}