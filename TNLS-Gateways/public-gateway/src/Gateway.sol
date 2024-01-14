// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";


    /*//////////////////////////////////////////////////////////////
                        Gateway Proxy
    //////////////////////////////////////////////////////////////*/
contract GatewayProxy is TransparentUpgradeableProxy {
    constructor(address _logic, address admin_, bytes memory _data) TransparentUpgradeableProxy(_logic, admin_, _data) {}
}

    /*//////////////////////////////////////////////////////////////
                    Secret VRF Interface
    //////////////////////////////////////////////////////////////*/
interface IRandomness {
    function fulfillRandomWords(uint256 requestId, uint256[] calldata randomWords) external;
}

contract Gateway is Initializable {
    /*//////////////////////////////////////////////////////////////
                              Constants
    //////////////////////////////////////////////////////////////*/

    //Use hard coded constant values instead of storage variables for Secret VRF, saves around 8,500 in gas per TX. 
    //Since contract is upgradeable, we can update these values as well with it.
    bytes constant routing_info = "secret1l4hr7wt4mm2fnvv5493ljlcngnfv2ewndk7tpc";
    bytes constant routing_code_hash = "2a8c936d011446c0ae1f2503b4fb86455b7dc2c6899a56bd74edf9636f9517db";
    string constant task_destination_network = "pulsar-3";


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
        string task_destination_network;
        string handle;
        bytes12 nonce;
        bytes payload;
        bytes payload_signature;
    }

    struct PostExecutionInfo {
        bytes32 payload_hash;
        bytes32 input_hash;
        bytes32 packet_hash;
        bytes20 callback_address;
        bytes4 callback_selector;
        bytes4 callback_gas_limit;
        bytes packet_signature;
        bytes result;
    }

    /*//////////////////////////////////////////////////////////////
                            State Variables
    //////////////////////////////////////////////////////////////*/
    
    address public owner;
    address public masterVerificationAddress;
    uint256 public taskId;

    /// @dev Task ID ====> ReducedTask
    mapping(uint256 => ReducedTask) public tasks;

    /// @dev mapping of chain name string to the verification address
    mapping(string => address) public route;

    /*//////////////////////////////////////////////////////////////
                              Errors
    //////////////////////////////////////////////////////////////*/

    /// @notice thrown when the signature s is invalid
    error InvalidSignatureSValue();

    /// @notice thrown when the signature length is invalid
    error InvalidSignatureLength();

    /// @notice thrown when the signature is invalid
    error InvalidSignature();


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

    /// @notice Splits a signature into its r, s, and v components
    /// @param _sig The signature to split
    /// @return r The r component of the signature
    /// @return s The s component of the signature
    /// @return v The recovery byte of the signature

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

    /// @notice Recovers the signer address from a message hash and a signature
    /// @param _signedMessageHash The hash of the signed message
    /// @param _signature The signature
    /// @return The address of the signer

    function recoverSigner(bytes32 _signedMessageHash, bytes memory _signature) private pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);
        return ecrecover(_signedMessageHash, v, r, s);
    }

    /// @notice Calculates the keccak256 hash of the route name and verification address
    /// @param _routeInput The route name
    /// @param _verificationAddressInput The verification address
    /// @return The calculated hash

    function getRouteHash(string calldata _routeInput, address _verificationAddressInput) private pure returns (bytes32) {
        return keccak256(abi.encode(_routeInput, _verificationAddressInput));
    }

    /// @notice Slices the last byte of an bytes32 to make it into a bytes31
    /// @param data The bytes32 data
    /// @return The sliced bytes31 data

    function sliceLastByte(bytes32 data) private pure returns (bytes31) {
        return bytes31(data & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00);
    }


    /// @notice Encodes a bytes memory array into a Base64 string
    /// @param data The bytes memory data to encode
    /// @return The Base64 encoded string

    function encodeBase64(bytes memory data) private pure returns (string memory) {
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

    /// @notice Converts a uint256 value into its string representation
    /// @param value The uint256 value to convert
    /// @return ptr The string representation of the uint256 value

    function uint256toString(uint256 value) private pure returns (string memory ptr) {
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
    
    /// @notice Converts a bytes memory array to an array of uint256
    /// @param data The bytes memory data to convert
    /// @return The array of uint256
    
   function bytesToUint256Array(bytes memory data) private pure returns (uint256[] memory) {
        require(data.length % 32 == 0, "Data length must be a multiple of 32 bytes");
        uint256[] memory uintArray;
        assembly {
            // Cast the bytes array to a uint256[] array by setting the appropriate length
            uintArray := data
            mstore(uintArray, div(mload(data), 32))
        }
        return uintArray;
    }

    /*//////////////////////////////////////////////////////////////
                              Events
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a new request comes into the gateway; to be picked up by the relayer
    event logNewTask(
        uint256 indexed task_id,
        string source_network,
        address user_address,
        string routing_info,
        bytes32 payload_hash,
        ExecutionInfo info
    );

    /// @notice Emitted when we recieve callback for our result of the computation
    event ComputedResult(uint256 taskId, bytes result);

    /*//////////////////////////////////////////////////////////////
                              Modifiers
    //////////////////////////////////////////////////////////////*/

    modifier onlyOwner() {
        require(msg.sender == owner, "UNAUTHORIZED");
        _;
    }

     /*//////////////////////////////////////////////////////////////
                             Initializer
    //////////////////////////////////////////////////////////////*/

    /// @notice Replaces the constructor for upgradeable contracts

    function initialize() public initializer {
        owner = msg.sender;
        taskId = 1;
    }

    /*//////////////////////////////////////////////////////////////
                        Maintainance Functions
    //////////////////////////////////////////////////////////////*/

    /// @notice Initialize the verification address
    /// @param _masterVerificationAddress The input address

    function setMasterVerificationAddress(address _masterVerificationAddress) external onlyOwner {
        masterVerificationAddress = _masterVerificationAddress;
    }

    /// @notice Updating the route
    /// @param _route Route name
    /// @param _verificationAddress Address corresponding to the route
    /// @param _signature Signed hashed inputs(_route + _verificationAddress)

    function updateRoute(string calldata _route, address _verificationAddress, bytes calldata _signature) external onlyOwner {
        bytes32 routeHash = getRouteHash(_route, _verificationAddress);
        bytes32 ethSignedMessageHash = keccak256(bytes.concat("\x19Ethereum Signed Message:\n32", routeHash));

        if (recoverSigner(ethSignedMessageHash, _signature) != masterVerificationAddress) {
            revert InvalidSignature();
        }

        route[_route] = _verificationAddress;
    }

    /// @notice Increase the task_id to check for problems 
    /// @param _newTaskId Route name

    function increaseTaskId(uint256 _newTaskId) external onlyOwner {
        require (_newTaskId > taskId, "New task id must be higher than the old task_id");
        taskId = _newTaskId;
    }

    /*//////////////////////////////////////////////////////////////
                             Pre Execution
    //////////////////////////////////////////////////////////////*/

    /// @notice Creates a new task with provided execution info
    /// @param _payloadHash Hash of the payload
    /// @param _userAddress Address of the user
    /// @param _routingInfo Routing information
    /// @param _info Execution information

    function send(        
        bytes32 _payloadHash,
        address _userAddress,
        string calldata _routingInfo,
        ExecutionInfo calldata _info) 
        external payable {

        // Payload hash verification
        if (keccak256(bytes.concat("\x19Ethereum Signed Message:\n32", keccak256(_info.payload))) != _payloadHash) {
            revert InvalidPayloadHash();
        }

        // Payload signature verification
        if (recoverSigner(_payloadHash, _info.payload_signature) != _userAddress) {
            revert InvalidSignature();
        }

        // persisting the task
        tasks[taskId] = ReducedTask(sliceLastByte(_payloadHash), false);

        //emit the task to be picked up by the relayer
        emit logNewTask(
            taskId,
            uint256toString(block.chainid),
            _userAddress,
            _routingInfo,
            _payloadHash,
            _info
        );

        //Increase the taskId to be used in the next gateway call. 
	    taskId++;
    }

    /// @notice Requests random words for VRF
    /// @param _numWords The number of random words requested
    /// @param _callbackGasLimit The gas limit for the callback
    /// @return requestId The request ID for the random words

    function requestRandomness(
        uint32 _numWords,
        uint32 _callbackGasLimit
    ) external payable returns (uint256 requestId) {

        //Set limit on how many random words can be requested
        require(_numWords <= 2000, "Too many words requested");

        //Encode the callback_address as Base64
        string memory callback_address = encodeBase64(bytes.concat(bytes20(msg.sender)));

        //construct the payload that is sent into the Secret Gateway by hand
        bytes memory payload = bytes.concat(
            '{"data":"{\\"numWords\\":',
            bytes(uint256toString(_numWords)),
            '}","routing_info": "',routing_info,
            '","routing_code_hash": "',routing_code_hash,
            '","user_address": "0x0000000000000000000000000000000000000000","user_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",', //unused user_address here + + 33 bytes of zeros in base64 for user_key
            '"callback_address": "', bytes(callback_address),
            '","callback_selector": "OLpGFA==",', // 0x38ba4614 hex value already converted into base64, callback_selector of the fullfillRandomWords function
            '"callback_gas_limit": ', bytes(uint256toString(_callbackGasLimit)),'}' 
        );

        //generate the payload hash using the ethereum hash format for messages
        bytes32 payloadHash = keccak256(bytes.concat("\x19Ethereum Signed Message:\n32", keccak256(payload)));

        // ExecutionInfo struct
        ExecutionInfo memory executionInfo = ExecutionInfo({
            user_key: new bytes(33), // equals AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA in base64
            user_pubkey: new bytes(64), // Fill with 0 bytes
            routing_code_hash: string(routing_code_hash),
            task_destination_network: task_destination_network,
            handle: "request_random",
            nonce: bytes12(0),
            payload: payload,
            payload_signature: new bytes(64) // empty signature, fill with 0 bytes
        });

        // persisting the task
        tasks[taskId] = ReducedTask(sliceLastByte(payloadHash), false);

        //emit the task to be picked up by the relayer
        emit logNewTask(
            taskId,
            uint256toString(block.chainid),
            tx.origin,
            string(routing_info),
            payloadHash,
            executionInfo
        );

        //Output the current task_id / request_id to the user and increase the taskId to be used in the next gateway call. 
        uint256 oldTaskId = taskId;
        taskId++;
        return oldTaskId;
    }

    /*//////////////////////////////////////////////////////////////
                             Post Execution
    //////////////////////////////////////////////////////////////*/

    /// @notice Handles the post-execution logic of a task
    /// @param _taskId The ID of the task
    /// @param _sourceNetwork The source network of the task
    /// @param _info Post execution information

    function postExecution(uint256 _taskId, string calldata _sourceNetwork, PostExecutionInfo calldata _info) external {
        
        ReducedTask storage task = tasks[_taskId];

        // Check if the task is already completed
        if (task.completed) {
            revert TaskAlreadyCompleted();
        }

        // Check if the payload hashes match
        if (sliceLastByte(_info.payload_hash) != task.payload_hash_reduced) {
            revert InvalidPayloadHash();
        }

        // Concatenate packet data elements
        bytes memory data =  bytes.concat(
        bytes(_sourceNetwork),
        bytes(uint256toString(block.chainid)),
        bytes32(_taskId),
        _info.input_hash,
        _info.payload_hash,
        _info.result,
        _info.callback_address,
        _info.callback_selector);
        
        // Perform Keccak256 + sha256 hash
        bytes32 packetHash = sha256(abi.encodePacked(keccak256(data)));

        // Packet signature verification
        if ((_info.packet_hash != packetHash) || 
            recoverSigner(_info.packet_hash, _info.packet_signature) != route[_sourceNetwork]) {
            revert InvalidPacketSignature();
        }
        
        //Mark the task as completed
        task.completed = true;

        // Continue with the function execution

        // Additional conversion for Secret VRF into uint256[] if callback_selector matches the fullfillRandomWords selector.
        if (_info.callback_selector == bytes4(0x38ba4614)) {
            uint256[] memory randomWords = bytesToUint256Array(_info.result);
            IRandomness randomness = IRandomness(address(_info.callback_address));
            randomness.fulfillRandomWords(_taskId, randomWords);
        }
        else {
            bool val; 
            (val, ) = address(_info.callback_address).call{gas: uint32(_info.callback_gas_limit)}(
                abi.encodeWithSelector(_info.callback_selector, _taskId, _info.result)
            );
            if (!val) { 
                revert CallbackError();
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                               Callback
    //////////////////////////////////////////////////////////////*/

    /// @notice Emits an event with the result of a computation
    /// @param _taskId The ID of the task
    /// @param _result The result of the computation

    function callback(uint256 _taskId, bytes calldata _result) external {
        emit ComputedResult(_taskId, _result);
    }

     /*//////////////////////////////////////////////////////////////
                     New Functions for Upgradeability
    //////////////////////////////////////////////////////////////*/
}