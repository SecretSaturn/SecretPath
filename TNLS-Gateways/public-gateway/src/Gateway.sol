// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";


contract Gateway is Initializable, OwnableUpgradeable {
    /*//////////////////////////////////////////////////////////////
                              Constants
    //////////////////////////////////////////////////////////////*/

    //Use hard coded constant values instead of storage variables for Secret VRF, saves around 10,000+ in gas per TX. 
    //Since contract is upgradeable, we can update these values as well with it.

    bytes constant routing_info = "secret16pcjalfuy72r4k26r4kn5f5x64ruzv30knflwx";
    bytes constant routing_code_hash = "49ffed0df451622ac1865710380c14d4af98dca2d32342bb20f2b22faca3d00d";
    string constant task_destination_network = "secret-4";
    address constant secret_gateway_signer_address = 0x88e43F4016f8282Ea6235aC069D02BA1cE5417aB;

    /*//////////////////////////////////////////////////////////////
                              Structs
    //////////////////////////////////////////////////////////////*/

    struct Task {
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
        uint32 callback_gas_limit;
        bytes payload;
        bytes payload_signature;
    }

    struct PostExecutionInfo {
        bytes32 payload_hash;
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
    
    uint256 public taskId;

    /// @dev Task ID ====> Task
    mapping(uint256 => Task) public tasks;

    /*//////////////////////////////////////////////////////////////
                              Errors
    //////////////////////////////////////////////////////////////*/

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

    /// @notice thrown when the Bytes Length is not a multiple of 32 bytes
    error InvalidBytesLength();

    /// @notice thrown when the user requests more Random Words than allowed
    error TooManyVRFRandomWordsRequested();

    /// @notice thrown when the paid fee was lower than expected: 
    error PaidRequestFeeTooLow();

    /*//////////////////////////////////////////////////////////////
                              Helpers
    //////////////////////////////////////////////////////////////*/

    /// @notice Splits a signature into its r, s, and v components
    /// @param _sig The signature to split
    /// @return r The r component of the signature
    /// @return s The s component of the signature
    /// @return v The recovery byte of the signature

    function splitSignature(bytes memory _sig) private pure returns (bytes32 r, bytes32 s, uint8 v) {
        if (_sig.length != 65) {
            revert InvalidSignatureLength();
        }

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

    function recoverSigner(bytes32 _signedMessageHash, bytes calldata _signature) private pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);
        return ecrecover(_signedMessageHash, v, r, s);
    }

    /// @notice Slices the last byte of an bytes32 to make it into a bytes31
    /// @param data The bytes32 data
    /// @return slicedData The sliced bytes31 data

   function sliceLastByte(bytes32 data) private pure returns (bytes31 slicedData) {
        assembly {
            // Shift the data right by 8 bits, effectively slicing off the last byte
            slicedData := shr(8, data)
        }
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
    
   function bytesToUInt256Array(bytes memory data) private pure returns (uint256[] memory) {
        if (data.length % 32 != 0) {
            revert InvalidBytesLength();
        }
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

    /// @notice Emitted when the callback was completed
    event TaskCompleted(uint256 taskId, bool callbackSuccessful);

    /*//////////////////////////////////////////////////////////////
                             Initializer
    //////////////////////////////////////////////////////////////*/

    /// @notice Replaces the constructor for upgradeable contracts

    function initialize() public initializer {
        __Ownable_init(msg.sender);
        taskId = 1;
    }

    constructor() {
        _disableInitializers();
    }

    /*//////////////////////////////////////////////////////////////
                        Maintainance Functions
    //////////////////////////////////////////////////////////////*/

    /// @notice Increase the task_id if needed
    /// @param _newTaskId the new task_id

    function increaseTaskId(uint256 _newTaskId) external onlyOwner {
        require (_newTaskId > taskId, "New task id must be higher than the old task_id");
        taskId = _newTaskId;
    }

    /// @notice Payout the paid balance to the owner

    function payoutBalance() external onlyOwner {
        payable(owner()).transfer(address(this).balance);
    }

    /*//////////////////////////////////////////////////////////////
                    Gas Price Payment Functions
    //////////////////////////////////////////////////////////////*/

    /// @notice Increase the task_id to check for problems 
    /// @param _callbackGasLimit the Callback Gas Limit

    function estimateRequestPrice(uint32 _callbackGasLimit) private view returns (uint256) {
        uint256 baseFee = _callbackGasLimit*block.basefee;
        return baseFee;
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
        
        //checks if enough gas was paid
        if (estimateRequestPrice(_info.callback_gas_limit) > msg.value) {
            revert PaidRequestFeeTooLow();
        }

        // Payload hash verification
        if (keccak256(bytes.concat("\x19Ethereum Signed Message:\n32", keccak256(_info.payload))) != _payloadHash) {
            revert InvalidPayloadHash();
        }

        // Payload signature verification
        if (recoverSigner(_payloadHash, _info.payload_signature) != _userAddress) {
            revert InvalidSignature();
        }

        // persisting the task
        tasks[taskId] = Task(sliceLastByte(_payloadHash), false);

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
        if (_numWords > 2000) {
           revert TooManyVRFRandomWordsRequested();
        }

        //checks if enough gas was paid for callback
        if (estimateRequestPrice(_callbackGasLimit) > msg.value) {
            revert PaidRequestFeeTooLow();
        }

        //Encode the callback_address as Base64
        string memory callback_address = encodeBase64(bytes.concat(bytes20(msg.sender)));

        //construct the payload that is sent into the Secret Gateway
        bytes memory payload = bytes.concat(
            '{"data":"{\\"numWords\\":',bytes(uint256toString(_numWords)),
            '}","routing_info": "',routing_info,
            '","routing_code_hash": "',routing_code_hash,
            '","user_address": "0x0000000000000000000000000000000000000000","user_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",', //unused user_address here + 33 bytes of zeros in base64 for user_key
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
            callback_gas_limit:_callbackGasLimit,
            payload: payload,
            payload_signature: new bytes(64) // empty signature, fill with 0 bytes
        });

        // persisting the task
        tasks[taskId] = Task(sliceLastByte(payloadHash), false);

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
        
        Task memory task = tasks[_taskId];

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
            bytes(uint256toString(_taskId)),
            _info.payload_hash,
            _info.result,
            _info.callback_address,
            _info.callback_selector
        );
        
        // Perform Keccak256 + sha256 hash
        bytes32 packetHash = sha256(bytes.concat(keccak256(data)));

        // Packet signature verification
        if (packetHash != _info.packet_hash || recoverSigner(packetHash, _info.packet_signature) != secret_gateway_signer_address) {
            revert InvalidPacketSignature();
        }
        
        //Mark the task as completed
        tasks[_taskId].completed = true;

        // Continue with the function execution

        // Additional conversion for Secret VRF into uint256[] if callback_selector matches the fullfillRandomWords selector.
        bool callbackSuccessful; 
        if (_info.callback_selector == 0x38ba4614) {
            uint256[] memory randomWords = bytesToUInt256Array(_info.result);
            (callbackSuccessful, ) = address(_info.callback_address).call(
                abi.encodeWithSelector(0x38ba4614, _taskId, randomWords)
            );
        }
        else {
            (callbackSuccessful, ) = address(_info.callback_address).call(
                abi.encodeWithSelector(_info.callback_selector, _taskId, _info.result)
            );
        }
        emit TaskCompleted(_taskId, callbackSuccessful);
    }

    /*//////////////////////////////////////////////////////////////
                     New Functions for Upgradeability
    //////////////////////////////////////////////////////////////*/

    function upgradeHandler() public {
    }
}