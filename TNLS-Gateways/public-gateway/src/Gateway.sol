// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";


contract Gateway is Initializable, OwnableUpgradeable {
    /*//////////////////////////////////////////////////////////////
                              Constants
    //////////////////////////////////////////////////////////////*/

    //Use hard coded constant values instead of storage variables for Secret VRF, saves around 10,000+ in gas per TX. 
    //Since contract is upgradeable, we can update these values as well with it.

    address constant secret_gateway_signer_address = 0x88e43F4016f8282Ea6235aC069D02BA1cE5417aB;
    string constant chainId = "534352";

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
                              Helpers
    //////////////////////////////////////////////////////////////*/

    function ethSignedPayloadHash(bytes memory payload) private pure returns (bytes32 payloadHash) {
        assembly {
            // Allocate memory for the data to hash
            let data := mload(0x40)
            mstore(data,"\x19Ethereum Signed Message:\n32")
            mstore(add(data, 28), keccak256(add(payload, 32), mload(payload)))
            payloadHash := keccak256(data, 60)
            mstore(0x40, add(data, 64))
        }
    }

    /// @notice Recovers the signer address from a message hash and a signature
    /// @param _signedMessageHash The hash of the signed message
    /// @param _signature The signature
    /// @return signerAddress The address of the signer

    function recoverSigner(bytes32 _signedMessageHash, bytes calldata _signature) private view returns (address signerAddress) {
        require(_signature.length == 65, "Invalid Signature Length");
        
        assembly {
            //Loading in v,s,r from _signature calldata is like this:
            //calldataload (4 bytes function selector + 32 bytes signed message hash + 32 bytes bytes _signature length 
            //+ 32 bytes per v (reads 32 bytes in)
            let m := mload(0x40) // Load free memory pointer
            mstore(0x40, add(m, 128)) // Update free memory pointer
            mstore(m, _signedMessageHash) // Store _signedMessageHash at memory location m
            mstore(add(m, 32), byte(0, calldataload(164))) // Load v from _signature and store at m + 32
            mstore(add(m, 64), calldataload(100)) // Load r from _signature and store at m + 64
            mstore(add(m, 96), calldataload(132)) // Load s from _signature and store at m + 96
            // Call ecrecover: returns 0 on error, address on success, 0 for failure
            if iszero(staticcall(gas(), 0x01, m, 128, m, 32)) {
                revert(0, 0)
            }
            //load result into result
            signerAddress := mload(m) 
        }
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
    /// @param data The bytes20 data to encode
    /// @return result The bytes28 encoded string

    function encodeAddressToBase64(bytes20 data) private pure returns (bytes28 result) {
        bytes memory table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        assembly {
            let resultPtr := mload(0x40) // Load free memory pointer
            table := add(table,1)
            mstore8(resultPtr, mload(add(table, and(shr(250, data), 0x3F))))
            mstore8(add(resultPtr, 1), mload(add(table, and(shr(244, data), 0x3F))))
            mstore8(add(resultPtr, 2), mload(add(table, and(shr(238, data), 0x3F))))
            mstore8(add(resultPtr, 3), mload(add(table, and(shr(232, data), 0x3F))))
            mstore8(add(resultPtr, 4), mload(add(table, and(shr(226, data), 0x3F))))
            mstore8(add(resultPtr, 5), mload(add(table, and(shr(220, data), 0x3F))))
            mstore8(add(resultPtr, 6), mload(add(table, and(shr(214, data), 0x3F))))
            mstore8(add(resultPtr, 7), mload(add(table, and(shr(208, data), 0x3F))))
            mstore8(add(resultPtr, 8), mload(add(table, and(shr(202, data), 0x3F))))
            mstore8(add(resultPtr, 9), mload(add(table, and(shr(196, data), 0x3F))))
            mstore8(add(resultPtr, 10), mload(add(table, and(shr(190, data), 0x3F))))
            mstore8(add(resultPtr, 11), mload(add(table, and(shr(184, data), 0x3F))))
            mstore8(add(resultPtr, 12), mload(add(table, and(shr(178, data), 0x3F))))
            mstore8(add(resultPtr, 13), mload(add(table, and(shr(172, data), 0x3F))))
            mstore8(add(resultPtr, 14), mload(add(table, and(shr(166, data), 0x3F))))
            mstore8(add(resultPtr, 15), mload(add(table, and(shr(160, data), 0x3F))))
            mstore8(add(resultPtr, 16), mload(add(table, and(shr(154, data), 0x3F))))
            mstore8(add(resultPtr, 17), mload(add(table, and(shr(148, data), 0x3F))))
            mstore8(add(resultPtr, 18), mload(add(table, and(shr(142, data), 0x3F))))
            mstore8(add(resultPtr, 19), mload(add(table, and(shr(136, data), 0x3F))))
            mstore8(add(resultPtr, 20), mload(add(table, and(shr(130, data), 0x3F)))) 
            mstore8(add(resultPtr, 21), mload(add(table, and(shr(124, data), 0x3F))))
            mstore8(add(resultPtr, 22), mload(add(table, and(shr(118, data), 0x3F))))
            mstore8(add(resultPtr, 23), mload(add(table, and(shr(112, data), 0x3F))))
            mstore8(add(resultPtr, 24), mload(add(table, and(shr(106, data), 0x3F))))
            mstore8(add(resultPtr, 25), mload(add(table, and(shr(100, data), 0x3F))))
            mstore8(add(resultPtr, 26), mload(add(table, and(shr(94, data), 0x3F))))
            mstore8(add(resultPtr, 27), 0x3d)
            result := mload(resultPtr)
            mstore(0x40, add(resultPtr,32))
        }
    }

    /// @notice Converts a uint256 value into its string representation
    /// @param x The uint256 value to convert
    /// @return s The string representation of the uint256 value

    function uint256toString(uint256 x) private pure returns (string memory s) {
        unchecked {
            if (x < 1e31) { 
                uint256 c1 = itoa31(x);
                assembly {
                    s := mload(0x40) // Set s to point to the free memory pointer
                    let z := shr(248, c1)
                    mstore(s, z) // Allocate 32 bytes for the string length
                    mstore(add(s, 32), shl(sub(256, mul(z, 8)), c1)) // Store c2 adjusted by z digits
                    mstore(0x40, add(s, 64)) // Update the free memory pointer
                }
            }   
            else if (x < 1e62) {
                uint256 c1 = itoa31(x);
                uint256 c2 = itoa31(x/1e31);
                assembly {
                    s := mload(0x40) // Set s to the free memory pointer
                    let z := shr(248, c2) // Extract the digit count for c2
                    mstore(s, add(z, 31)) // Allocate space for z digits of c2 + 31 bytes of c1
                    mstore(add(s, 32), shl(sub(256, mul(z, 8)), c2)) // Store c2 adjusted by z digits
                    mstore(add(s, add(32, z)), shl(8,c1)) // Store the last 31 bytes of c1
                    mstore(0x40, add(s, 96)) // Update the free memory pointer
                }
            } else {
                uint256 c1 = itoa31(x);
                uint256 c2 = itoa31(x/1e31);
                uint256 c3 = itoa31(x/1e62);
                assembly {
                    s := mload(0x40) // Set s to point to the free memory pointer
                    let z := shr(248, c3)
                    mstore(s, add(z, 62)) // Allocate 32 bytes for the string length
                    mstore(add(s, 32), shl(sub(256, mul(z, 8)), c3)) // Store c2 adjusted by z digits
                    mstore(add(s, add(32, z)), shl(8, c2)) // Store the last 31 bytes of c1
                    mstore(add(s, add(61, z)), shl(8, c1)) // Store the last 31 bytes of c1
                    mstore(0x40, add(s, 128)) // Update the free memory pointer to point beyond the allocated space
                }
            }
        }
    }
    /// @notice Helper function for UInt256 Conversion
    /// @param x The uint256 value to convert
    /// @return y The string representation of the uint256 value as a

    function itoa31 (uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = 0x0030303030303030303030303030303030303030303030303030303030303030;
            y += x % 10; y += (x / 1e1 % 10) << 8; y += (x / 1e2 % 10) << 16;
            if (x < 1e3) {
                if (x < 1e1) return y += 1 << 248;
                if (x < 1e2) return y += 2 << 248;
                return y += 3 << 248;
            }
            y += (x / 1e3 % 10) << 24; y += (x / 1e4 % 10) << 32; y += (x / 1e5 % 10) << 40;
            if (x < 1e6) {
                if (x < 1e4)  return y += 4 << 248;
                if (x < 1e5)  return y += 5 << 248;
                return  y += 6 << 248; 
            }
            y += (x / 1e6 % 10) << 48; y += (x / 1e7 % 10) << 56; y += (x / 1e8 % 10) << 64;
            if (x < 1e9) {
                if (x < 1e7) return y += 7 << 248;
                if (x < 1e8) return y += 8 << 248; 
                return y += 9 << 248; 
            }
            y += (x / 1e9 % 10) << 72; y += (x / 1e10 % 10) << 80; y += (x / 1e11 % 10) << 88;
            if (x < 1e12) {
                if (x < 1e10) return y += 10 << 248; 
                if (x < 1e11) return y += 11 << 248; 
                return y += 12 << 248; 
            }
            y += (x / 1e12 % 10) << 96; y += (x / 1e13 % 10) << 104; y += (x / 1e14 % 10) << 112;
            if (x < 1e15) {
                if (x < 1e13) return y += 13 << 248; 
                if (x < 1e14) return y += 14 << 248; 
                return y += 15 << 248; 
            }
            y += (x / 1e15 % 10) << 120; y += (x / 1e16 % 10) << 128; y += (x / 1e17 % 10) << 136;
            if (x < 1e18) {
                if (x < 1e16) return y += 16 << 248; 
                if (x < 1e17) return y += 17 << 248; 
                return y += 18 << 248; 
            }
            y += (x / 1e18 % 10) << 144; y += (x / 1e19 % 10) << 152; y += (x / 1e20 % 10) << 160;
            if (x < 1e21) {
                if (x < 1e19) return y += 19 << 248; 
                if (x < 1e20) return y += 20 << 248; 
                return y += 21 << 248; 
            }
            y += (x / 1e21 % 10) << 168; y += (x / 1e22 % 10) << 176; y += (x / 1e23 % 10) << 184;
            if (x < 1e24) {
                if (x < 1e22) return y += 22 << 248; 
                if (x < 1e23) return y += 23 << 248; 
                return y += 24 << 248; 
            }
            y += (x / 1e24 % 10) << 192; y += (x / 1e25 % 10) << 200; y += (x / 1e26 % 10) << 208;
            if (x < 1e27) {
                if (x < 1e25) return y += 25 << 248; 
                if (x < 1e26) return y += 26 << 248; 
                return y += 27 << 248; 
            }
            y += (x / 1e27 % 10) << 216; y += (x / 1e28 % 10) << 224; y += (x / 1e29 % 10) << 232;
            if (x < 1e30) {
                if (x < 1e28) return y += 28 << 248; 
                if (x < 1e29) return y += 29 << 248; 
                return y += 30 << 248; 
            }
            y += (x / 1e30 % 10) << 240; 
            return y += 31 << 248; 
        }
    }
    
    /// @notice Converts a bytes memory array to an array of uint256
    /// @param data The bytes memory data to convert
    /// @return uintArray The array of uint256
    
   function bytesToUInt256Array(bytes calldata data) private pure returns (uint256[] memory uintArray) {
        require(data.length % 32 == 0, "Invalid Bytes Length");

        assembly {
            uintArray := mload(0x40) 
            mstore(uintArray, div(data.length, 32)) 
            calldatacopy(add(uintArray,32), data.offset, data.length)
            mstore(0x40, add(add(uintArray, 32), data.length))
        }
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
    event TaskCompleted(uint256 indexed taskId, bool callbackSuccessful);

    /// @notice Emitted when the VRF callback was fulfilled
    event fulfilledRandomWords(uint256 indexed requestId);

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

    function estimateRequestPrice(uint32 _callbackGasLimit) private view returns (uint256 baseFee) {
        baseFee = _callbackGasLimit*tx.gasprice;
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
        
        uint256 estimatedPrice = estimateRequestPrice(_info.callback_gas_limit);

        //checks if enough gas was paid for callback
        if (estimatedPrice > msg.value) {
            require(false, "Paid Callback Fee Too Low");
        }
        else if (estimatedPrice < msg.value) {
            payable(tx.origin).transfer(msg.value - estimatedPrice);
        }

        // Payload hash verification
        require(ethSignedPayloadHash(_info.payload) == _payloadHash, "Invalid Payload Hash");

        // Payload signature verification
        require(recoverSigner(_payloadHash, _info.payload_signature) == _userAddress, "Invalid Payload Signature");

        // persisting the task
        tasks[taskId] = Task(sliceLastByte(_payloadHash), false);

        //emit the task to be picked up by the relayer
        emit logNewTask(
            taskId,
            chainId,
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

        uint256 _taskId = taskId;

        //Set limit on how many random words can be requested
        require(_numWords <= 2000, "Too Many VRF RandomWords Requested");

        uint256 estimatedPrice = estimateRequestPrice(_callbackGasLimit);

        //checks if enough gas was paid for callback
        if (estimatedPrice > msg.value) {
            require(false, "Paid Callback Fee Too Low");
        }
        else if (estimatedPrice < msg.value) {
            payable(tx.origin).transfer(msg.value - estimatedPrice);
        }

        //Encode the callback_address as Base64
        bytes28 callback_address = encodeAddressToBase64(bytes20(msg.sender));

        //construct the payload that is sent into the Secret Gateway
        bytes memory payload = bytes.concat(
            '{"data":"{\\"numWords\\":',
            bytes(uint256toString(_numWords)),
            '}","routing_info": "secret16pcjalfuy72r4k26r4kn5f5x64ruzv30knflwx","routing_code_hash": "49ffed0df451622ac1865710380c14d4af98dca2d32342bb20f2b22faca3d00d" ,"user_address": "0x0000","user_key": "AAA=", "callback_address": "', //unused user_address here + 2 bytes of zeros in base64 for user_key, add RNG Contract address & code hash on Secret 
            callback_address,
            '","callback_selector": "OLpGFA==", "callback_gas_limit": ', // 0x38ba4614 hex value already converted into base64, callback_selector of the fullfillRandomWords function
            bytes(uint256toString(_callbackGasLimit)),
            '}' 
        );

        //generate the payload hash using the ethereum hash format for messages
        bytes32 payloadHash = ethSignedPayloadHash(payload);

        bytes memory emptyBytes = hex"0000";

        // ExecutionInfo struct
        ExecutionInfo memory executionInfo = ExecutionInfo({
            user_key: emptyBytes, // equals AAA= in base64
            user_pubkey: emptyBytes, // Fill with 0 bytes
            routing_code_hash: "49ffed0df451622ac1865710380c14d4af98dca2d32342bb20f2b22faca3d00d", //RNG Contract codehash on Secret 
            task_destination_network: "secret-4",
            handle: "request_random",
            nonce: bytes12(0),
            callback_gas_limit: _callbackGasLimit,
            payload: payload,
            payload_signature: emptyBytes // empty signature, fill with 0 bytes
        });

        // persisting the task
        tasks[_taskId] = Task(sliceLastByte(payloadHash), false);

        //emit the task to be picked up by the relayer
        emit logNewTask(
            _taskId,
            chainId,
            tx.origin,
            "secret16pcjalfuy72r4k26r4kn5f5x64ruzv30knflwx", //RNG Contract address on Secret 
            payloadHash,
            executionInfo
        );

        //Output the current task_id / request_id to the user and increase the taskId to be used in the next gateway call. 
        taskId = _taskId + 1;
        requestId = _taskId;
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
        require(!task.completed,"Task Already Completed");

        // Check if the payload hashes match
        require(sliceLastByte(_info.payload_hash) == task.payload_hash_reduced, "Invalid Payload Hash");

        // Concatenate packet data elements
        bytes memory data =  bytes.concat(
            bytes(_sourceNetwork),
            bytes(chainId),
            bytes(uint256toString(_taskId)),
            _info.payload_hash,
            _info.result,
            _info.callback_address,
            _info.callback_selector
        );
        
        // Perform Keccak256 + sha256 hash
        //bytes32 packetHash = sha256(bytes.concat(keccak256(data)));

        //For EVM Chains that don't support the sha256 precompile
        bytes32 packetHash = hashSHA256(keccak256(data));

        // Packet signature verification
        require(packetHash == _info.packet_hash && recoverSigner(packetHash, _info.packet_signature) == secret_gateway_signer_address, "Invalid Packet Signature");
        
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
            emit fulfilledRandomWords(_taskId);
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
    function hashSHA256(bytes32 valueHash) private pure returns (bytes32 output) {
        // pad and format input into array of uint32 words 

        uint32 a = 0x6a09e667;
        uint32 b = 0xbb67ae85;
        uint32 c = 0x3c6ef372;
        uint32 d = 0xa54ff53a;
        uint32 e = 0x510e527f;
        uint32 f = 0x9b05688c;
        uint32 g = 0x1f83d9ab;
        uint32 h = 0x5be0cd19;

        unchecked {
            uint32[64] memory w;
            assembly {
                // this part that pads the data is from rage_pit
                let dataPtr := mload(0x40)
                mstore(dataPtr, valueHash)
                // pad message with 0b1
                mstore(add(32, dataPtr), shl(0xf8, 0x80))
                // end padding with message length
                mstore(add(56, dataPtr), shl(0xc0, 0x100))
                mstore(0x40, add(dataPtr, 64))
                //copy data into w directly
                mstore(add(w, 0x00), shr(0xe0, mload(dataPtr)))
                mstore(add(w, 0x20), shr(0xe0, mload(add(dataPtr, 0x04))))
                mstore(add(w, 0x40), shr(0xe0, mload(add(dataPtr, 0x08))))
                mstore(add(w, 0x60), shr(0xe0, mload(add(dataPtr, 0x0c))))
                mstore(add(w, 0x80), shr(0xe0, mload(add(dataPtr, 0x10))))
                mstore(add(w, 0xa0), shr(0xe0, mload(add(dataPtr, 0x14))))
                mstore(add(w, 0xc0), shr(0xe0, mload(add(dataPtr, 0x18))))
                mstore(add(w, 0xe0), shr(0xe0, mload(add(dataPtr, 0x1c))))
                mstore(add(w, 0x100), shr(0xe0, mload(add(dataPtr, 0x20))))
                mstore(add(w, 0x120), shr(0xe0, mload(add(dataPtr, 0x24))))
                mstore(add(w, 0x140), shr(0xe0, mload(add(dataPtr, 0x28))))
                mstore(add(w, 0x160), shr(0xe0, mload(add(dataPtr, 0x2c))))
                mstore(add(w, 0x180), shr(0xe0, mload(add(dataPtr, 0x30))))
                mstore(add(w, 0x1a0), shr(0xe0, mload(add(dataPtr, 0x34))))
                mstore(add(w, 0x1c0), shr(0xe0, mload(add(dataPtr, 0x38))))
                mstore(add(w, 0x1e0), shr(0xe0, mload(add(dataPtr, 0x3c))))
            }
            w[16] = w[0] + gamma0(w[1]) + w[9] + gamma1(w[14]);
            w[17] = w[1] + gamma0(w[2]) + w[10] + gamma1(w[15]);
            w[18] = w[2] + gamma0(w[3]) + w[11] + gamma1(w[16]);
            w[19] = w[3] + gamma0(w[4]) + w[12] + gamma1(w[17]);
            w[20] = w[4] + gamma0(w[5]) + w[13] + gamma1(w[18]);
            w[21] = w[5] + gamma0(w[6]) + w[14] + gamma1(w[19]);
            w[22] = w[6] + gamma0(w[7]) + w[15] + gamma1(w[20]);
            w[23] = w[7] + gamma0(w[8]) + w[16] + gamma1(w[21]);
            w[24] = w[8] + gamma0(w[9]) + w[17] + gamma1(w[22]);
            w[25] = w[9] + gamma0(w[10]) + w[18] + gamma1(w[23]);
            w[26] = w[10] + gamma0(w[11]) + w[19] + gamma1(w[24]);
            w[27] = w[11] + gamma0(w[12]) + w[20] + gamma1(w[25]);
            w[28] = w[12] + gamma0(w[13]) + w[21] + gamma1(w[26]);
            w[29] = w[13] + gamma0(w[14]) + w[22] + gamma1(w[27]);
            w[30] = w[14] + gamma0(w[15]) + w[23] + gamma1(w[28]);
            w[31] = w[15] + gamma0(w[16]) + w[24] + gamma1(w[29]);
            w[32] = w[16] + gamma0(w[17]) + w[25] + gamma1(w[30]);
            w[33] = w[17] + gamma0(w[18]) + w[26] + gamma1(w[31]);
            w[34] = w[18] + gamma0(w[19]) + w[27] + gamma1(w[32]);
            w[35] = w[19] + gamma0(w[20]) + w[28] + gamma1(w[33]);
            w[36] = w[20] + gamma0(w[21]) + w[29] + gamma1(w[34]);
            w[37] = w[21] + gamma0(w[22]) + w[30] + gamma1(w[35]);
            w[38] = w[22] + gamma0(w[23]) + w[31] + gamma1(w[36]);
            w[39] = w[23] + gamma0(w[24]) + w[32] + gamma1(w[37]);
            w[40] = w[24] + gamma0(w[25]) + w[33] + gamma1(w[38]);
            w[41] = w[25] + gamma0(w[26]) + w[34] + gamma1(w[39]);
            w[42] = w[26] + gamma0(w[27]) + w[35] + gamma1(w[40]);
            w[43] = w[27] + gamma0(w[28]) + w[36] + gamma1(w[41]);
            w[44] = w[28] + gamma0(w[29]) + w[37] + gamma1(w[42]);
            w[45] = w[29] + gamma0(w[30]) + w[38] + gamma1(w[43]);
            w[46] = w[30] + gamma0(w[31]) + w[39] + gamma1(w[44]);
            w[47] = w[31] + gamma0(w[32]) + w[40] + gamma1(w[45]);
            w[48] = w[32] + gamma0(w[33]) + w[41] + gamma1(w[46]);
            w[49] = w[33] + gamma0(w[34]) + w[42] + gamma1(w[47]);
            w[50] = w[34] + gamma0(w[35]) + w[43] + gamma1(w[48]);
            w[51] = w[35] + gamma0(w[36]) + w[44] + gamma1(w[49]);
            w[52] = w[36] + gamma0(w[37]) + w[45] + gamma1(w[50]);
            w[53] = w[37] + gamma0(w[38]) + w[46] + gamma1(w[51]);
            w[54] = w[38] + gamma0(w[39]) + w[47] + gamma1(w[52]);
            w[55] = w[39] + gamma0(w[40]) + w[48] + gamma1(w[53]);
            w[56] = w[40] + gamma0(w[41]) + w[49] + gamma1(w[54]);
            w[57] = w[41] + gamma0(w[42]) + w[50] + gamma1(w[55]);
            w[58] = w[42] + gamma0(w[43]) + w[51] + gamma1(w[56]);
            w[59] = w[43] + gamma0(w[44]) + w[52] + gamma1(w[57]);
            w[60] = w[44] + gamma0(w[45]) + w[53] + gamma1(w[58]);
            w[61] = w[45] + gamma0(w[46]) + w[54] + gamma1(w[59]);
            w[62] = w[46] + gamma0(w[47]) + w[55] + gamma1(w[60]);
            w[63] = w[47] + gamma0(w[48]) + w[56] + gamma1(w[61]);

            // Round 0
            uint32 temp1 = h + sigma1(e) + Ch(e,f,g) + 0x428a2f98 + w[0];
            uint32 temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 1
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x71374491 + w[1];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 2
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xb5c0fbcf + w[2];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 3
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xe9b5dba5 + w[3];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 4
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x3956c25b + w[4];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 5
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x59f111f1 + w[5];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 6
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x923f82a4 + w[6];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 7
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xab1c5ed5 + w[7];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 8
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xd807aa98 + w[8];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 9
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x12835b01 + w[9];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 10
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x243185be + w[10];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 11
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x550c7dc3 + w[11];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 12
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x72be5d74 + w[12];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 13
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x80deb1fe + w[13];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 14
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x9bdc06a7 + w[14];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 15
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xc19bf174 + w[15];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 16
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xe49b69c1 + w[16];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 17
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xefbe4786 + w[17];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 18
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x0fc19dc6 + w[18];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 19
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x240ca1cc + w[19];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 20
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x2de92c6f + w[20];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 21
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x4a7484aa + w[21];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 22
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x5cb0a9dc + w[22];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 23
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x76f988da + w[23];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 24
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x983e5152 + w[24];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 25
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xa831c66d + w[25];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 26
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xb00327c8 + w[26];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 27
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xbf597fc7 + w[27];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 28
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xc6e00bf3 + w[28];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 29
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xd5a79147 + w[29];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 30
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x06ca6351 + w[30];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 31
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x14292967 + w[31];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 32
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x27b70a85 + w[32];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 33
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x2e1b2138 + w[33];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 34
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x4d2c6dfc + w[34];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 35
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x53380d13 + w[35];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 36
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x650a7354 + w[36];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 37
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x766a0abb + w[37];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 38
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x81c2c92e + w[38];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 39
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x92722c85 + w[39];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 40
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xa2bfe8a1 + w[40];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 41
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xa81a664b + w[41];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 42
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xc24b8b70 + w[42];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 43
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xc76c51a3 + w[43];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 44
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xd192e819 + w[44];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 45
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xd6990624 + w[45];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 46
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xf40e3585 + w[46];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 47
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x106aa070 + w[47];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 48
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x19a4c116 + w[48];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 49
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x1e376c08 + w[49];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 50
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x2748774c + w[50];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 51
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x34b0bcb5 + w[51];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 52
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x391c0cb3 + w[52];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 53
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x4ed8aa4a + w[53];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 54
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x5b9cca4f + w[54];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 55
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x682e6ff3 + w[55];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 56
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x748f82ee + w[56];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 57
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x78a5636f + w[57];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 58
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x84c87814 + w[58];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 59
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x8cc70208 + w[59];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 60
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x90befffa + w[60];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 61
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xa4506ceb + w[61];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 62
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xbef9a3f7 + w[62];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 63
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xc67178f2 + w[63];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            assembly {
                let ptr := mload(0x40)
                mstore(ptr, shl(0xe0, add(0x6a09e667,a)))
                mstore(add(ptr, 0x04), shl(0xe0, add(0xbb67ae85,b)))
                mstore(add(ptr, 0x08), shl(0xe0, add(0x3c6ef372,c)))
                mstore(add(ptr, 0x0c), shl(0xe0, add(0xa54ff53a,d)))
                mstore(add(ptr, 0x10), shl(0xe0, add(0x510e527f,e)))
                mstore(add(ptr, 0x14), shl(0xe0, add(0x9b05688c,f)))
                mstore(add(ptr, 0x18), shl(0xe0, add(0x1f83d9ab,g)))
                mstore(add(ptr, 0x1c), shl(0xe0, add(0x5be0cd19,h)))
                mstore(0x40, add(ptr,0x20)) //update free memory pointer
                output := mload(ptr)
            }
        }
    }    
    
    //do NOT change uint256 to uint32 here or it will break the memory layout for the shifts
    function sigma0(uint256 x) private pure returns (uint32 result) {
        assembly {result := xor(xor(or(shr(2, x),shl(30,x)),or(shr(13, x),shl(19,x))),or(shr(22, x),shl(10,x)))}
    }
    //do NOT change uint256 to uint32 here or it will break the memory layout for the shifts
    function sigma1(uint256 x) private pure returns (uint32 result) {
       assembly {result := xor(xor(or(shr(6, x),shl(26,x)),or(shr(11, x),shl(21,x))),or(shr(25, x),shl(7,x)))}
    }

    function gamma0(uint32 x) private pure returns (uint32 result) {
        assembly {result := xor(xor(or(shr(7, x), shl(25, x)), or(shr(18, x), shl(14, x))), shr(3, x))}
    }

    function gamma1(uint32 x) private pure returns (uint32 result) {
        assembly {result := xor(xor(or(shr(17, x), shl(15, x)), or(shr(19, x), shl(13, x))), shr(10, x))}
    }

   function Ch(uint32 x, uint32 y, uint32 z) private pure returns (uint32 result) {
        assembly {result := xor(z, and(x, xor(y, z)))}
    }

    function Maj(uint32 x, uint32 y, uint32 z) private pure returns (uint32 result) {
        assembly {result := or(and(or(x, y), z), and(x, y))}
    }
}