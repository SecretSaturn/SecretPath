// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import {Util} from "../src/Util.sol";
import "../src/interfaces/IGateway.sol";

contract Gateway is IGateway {
    using Util for *;

    /// @notice thrown when the signature is invalid
    error InvalidSignature();

    /// @notice thrown when the PayloadHash is invalid
    error InvalidPayloadHash();

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
        bytes32 routeHash = Util.getRouteHash(_route, _verificationAddress);
        bytes32 ethSignedMessageHash = Util.getEthSignedMessageHash(routeHash);

        bool verifySig;
        verifySig = Util.recoverSigner(ethSignedMessageHash, _signature) == masterVerificationAddress;

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
    mapping(uint256 => Util.Task) public tasks;

    /// @notice Pre-Execution
    /// @param _task Task struct
    /// @param _info ExecutionInfo struct
    function preExecution(Util.Task memory _task, Util.ExecutionInfo memory _info) public {
        bool verifySig;

        // Payload hash signature verification
        verifySig = true;
        verifySig = Util.recoverSigner(_task.payload_hash, _info.payload_signature) == _task.user_address;

        if (!verifySig) {
            revert InvalidSignature();
        }

        // persisting the task
        tasks[taskId] = _task;

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
    function postExecution(uint256 _taskId, string memory _sourceNetwork, Util.PostExecutionInfo memory _info) public {
        bool verifySig;
        address recoveredSigner;

        address checkerAddress = route[_sourceNetwork];

        // Payload signature verification
        verifySig = true;
        recoveredSigner = Util.modifiedRecoverSigner(_info.payload_hash, _info.payload_signature, checkerAddress);
        verifySig = recoveredSigner == checkerAddress;
        if (!verifySig) {
            revert InvalidSignature();
        }

        // Payload hash verification from tasks struct
        bool verifyPayloadHash;
        verifyPayloadHash = _info.payload_hash == tasks[_taskId].payload_hash;
        if (!verifyPayloadHash) {
            revert InvalidPayloadHash();
        }

        // Result signature verification
        verifySig = true;
        recoveredSigner = Util.modifiedRecoverSigner(_info.result_hash, _info.result_signature, checkerAddress);
        verifySig = recoveredSigner == checkerAddress;
        if (!verifySig) {
            revert InvalidSignature();
        }

        // Packet signature verification
        verifySig = true;
        recoveredSigner = Util.modifiedRecoverSigner(_info.packet_hash, _info.packet_signature, checkerAddress);
        verifySig = recoveredSigner == checkerAddress;
        if (!verifySig) {
            revert InvalidSignature();
        }

        (bool val,) = address(tasks[_taskId].callback_address).call(abi.encodeWithSelector(tasks[_taskId].callback_selector, _taskId, _info.result));
        require(val == true, "Callback error");

        tasks[_taskId].completed = true;

        emit logCompletedTask(_taskId, _info.payload_hash, _info.result_hash);
    }
}
