// SPDX-License-Identifier: Apache-2.0
// Version: 0.2.3
pragma solidity ^0.8.25;


/*//////////////////////////////////////////////////////////////
                Open Zeppelin Libraries
//////////////////////////////////////////////////////////////*/

/**
 * @dev This is a base contract to aid in writing upgradeable contracts, or any kind of contract that will be deployed
 * behind a proxy. Since proxied contracts do not make use of a constructor, it's common to move constructor logic to an
 * external initializer function, usually called `initialize`. It then becomes necessary to protect this initializer
 * function so it can only be called once. The {initializer} modifier provided by this contract will have this effect.
 *
 * The initialization functions use a version number. Once a version number is used, it is consumed and cannot be
 * reused. This mechanism prevents re-execution of each "step" but allows the creation of new initialization steps in
 * case an upgrade adds a module that needs to be initialized. */

abstract contract Initializable {
    /**
     * @dev Storage of the initializable contract.
     *
     * It's implemented on a custom ERC-7201 namespace to reduce the risk of storage collisions
     * when using with upgradeable contracts.
     *
     * @custom:storage-location erc7201:openzeppelin.storage.Initializable
     */
    struct InitializableStorage {
        /**
         * @dev Indicates that the contract has been initialized.
         */
        uint64 _initialized;
        /**
         * @dev Indicates that the contract is in the process of being initialized.
         */
        bool _initializing;
    }

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.Initializable")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant INITIALIZABLE_STORAGE = 0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00;

    /**
     * @dev The contract is already initialized.
     */
    error InvalidInitialization();

    /**
     * @dev The contract is not initializing.
     */
    error NotInitializing();

    /**
     * @dev Triggered when the contract has been initialized or reinitialized.
     */
    event Initialized(uint64 version);

    /**
     * @dev A modifier that defines a protected initializer function that can be invoked at most once. In its scope,
     * `onlyInitializing` functions can be used to initialize parent contracts.
     *
     * Similar to `reinitializer(1)`, except that in the context of a constructor an `initializer` may be invoked any
     * number of times. This behavior in the constructor can be useful during testing and is not expected to be used in
     * production.
     *
     * Emits an {Initialized} event.
     */
    modifier initializer() {
        // solhint-disable-next-line var-name-mixedcase
        InitializableStorage storage $ = _getInitializableStorage();

        // Cache values to avoid duplicated sloads
        bool isTopLevelCall = !$._initializing;
        uint64 initialized = $._initialized;

        // Allowed calls:
        // - initialSetup: the contract is not in the initializing state and no previous version was
        //                 initialized
        // - construction: the contract is initialized at version 1 (no reininitialization) and the
        //                 current contract is just being deployed
        bool initialSetup = initialized == 0 && isTopLevelCall;
        bool construction = initialized == 1 && address(this).code.length == 0;

        if (!initialSetup && !construction) {
            revert InvalidInitialization();
        }
        $._initialized = 1;
        if (isTopLevelCall) {
            $._initializing = true;
        }
        _;
        if (isTopLevelCall) {
            $._initializing = false;
            emit Initialized(1);
        }
    }

    /**
     * @dev A modifier that defines a protected reinitializer function that can be invoked at most once, and only if the
     * contract hasn't been initialized to a greater version before. In its scope, `onlyInitializing` functions can be
     * used to initialize parent contracts.
     *
     * A reinitializer may be used after the original initialization step. This is essential to configure modules that
     * are added through upgrades and that require initialization.
     *
     * When `version` is 1, this modifier is similar to `initializer`, except that functions marked with `reinitializer`
     * cannot be nested. If one is invoked in the context of another, execution will revert.
     *
     * Note that versions can jump in increments greater than 1; this implies that if multiple reinitializers coexist in
     * a contract, executing them in the right order is up to the developer or operator.
     *
     * WARNING: Setting the version to 2**64 - 1 will prevent any future reinitialization.
     *
     * Emits an {Initialized} event.
     */
    modifier reinitializer(uint64 version) {
        // solhint-disable-next-line var-name-mixedcase
        InitializableStorage storage $ = _getInitializableStorage();

        if ($._initializing || $._initialized >= version) {
            revert InvalidInitialization();
        }
        $._initialized = version;
        $._initializing = true;
        _;
        $._initializing = false;
        emit Initialized(version);
    }

    /**
     * @dev Modifier to protect an initialization function so that it can only be invoked by functions with the
     * {initializer} and {reinitializer} modifiers, directly or indirectly.
     */
    modifier onlyInitializing() {
        _checkInitializing();
        _;
    }

    /**
     * @dev Reverts if the contract is not in an initializing state. See {onlyInitializing}.
     */
    function _checkInitializing() internal view virtual {
        if (!_isInitializing()) {
            revert NotInitializing();
        }
    }

    /**
     * @dev Locks the contract, preventing any future reinitialization. This cannot be part of an initializer call.
     * Calling this in the constructor of a contract will prevent that contract from being initialized or reinitialized
     * to any version. It is recommended to use this to lock implementation contracts that are designed to be called
     * through proxies.
     *
     * Emits an {Initialized} event the first time it is successfully executed.
     */
    function _disableInitializers() internal virtual {
        // solhint-disable-next-line var-name-mixedcase
        InitializableStorage storage $ = _getInitializableStorage();

        if ($._initializing) {
            revert InvalidInitialization();
        }
        if ($._initialized != type(uint64).max) {
            $._initialized = type(uint64).max;
            emit Initialized(type(uint64).max);
        }
    }

    /**
     * @dev Returns the highest version that has been initialized. See {reinitializer}.
     */
    function _getInitializedVersion() internal view returns (uint64) {
        return _getInitializableStorage()._initialized;
    }

    /**
     * @dev Returns `true` if the contract is currently initializing. See {onlyInitializing}.
     */
    function _isInitializing() internal view returns (bool) {
        return _getInitializableStorage()._initializing;
    }

    /**
     * @dev Returns a pointer to the storage namespace.
     */
    // solhint-disable-next-line var-name-mixedcase
    function _getInitializableStorage() private pure returns (InitializableStorage storage $) {
        assembly {
            $.slot := INITIALIZABLE_STORAGE
        }
    }
}

/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract ContextUpgradeable is Initializable {
    function __Context_init() internal onlyInitializing {
    }

    function __Context_init_unchained() internal onlyInitializing {
    }
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }

    function _contextSuffixLength() internal view virtual returns (uint256) {
        return 0;
    }
}


/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * The initial owner is set to the address provided by the deployer. This can
 * later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */

abstract contract OwnableUpgradeable is Initializable, ContextUpgradeable {
    /// @custom:storage-location erc7201:openzeppelin.storage.Ownable
    struct OwnableStorage {
        address _owner;
    }

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.Ownable")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant OwnableStorageLocation = 0x9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300;

    function _getOwnableStorage() private pure returns (OwnableStorage storage $) {
        assembly {
            $.slot := OwnableStorageLocation
        }
    }

    /**
     * @dev The caller account is not authorized to perform an operation.
     */
    error OwnableUnauthorizedAccount(address account);

    /**
     * @dev The owner is not a valid owner account. (eg. `address(0)`)
     */
    error OwnableInvalidOwner(address owner);

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the address provided by the deployer as the initial owner.
     */
    function __Ownable_init(address initialOwner) internal onlyInitializing {
        __Ownable_init_unchained(initialOwner);
    }

    function __Ownable_init_unchained(address initialOwner) internal onlyInitializing {
        if (initialOwner == address(0)) {
            revert OwnableInvalidOwner(address(0));
        }
        _transferOwnership(initialOwner);
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view virtual returns (address) {
        OwnableStorage storage $ = _getOwnableStorage();
        return $._owner;
    }

    /**
     * @dev Throws if the sender is not the owner.
     */
    function _checkOwner() internal view virtual {
        if (owner() != _msgSender()) {
            revert OwnableUnauthorizedAccount(_msgSender());
        }
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby disabling any functionality that is only available to the owner.
     */
    function renounceOwnership() public virtual onlyOwner {
        _transferOwnership(address(0));
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        if (newOwner == address(0)) {
            revert OwnableInvalidOwner(address(0));
        }
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual {
        OwnableStorage storage $ = _getOwnableStorage();
        address oldOwner = $._owner;
        $._owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}

contract Gateway is Initializable, OwnableUpgradeable {
    /*//////////////////////////////////////////////////////////////
                              Constants
    //////////////////////////////////////////////////////////////*/

    //Use hard coded constant values instead of storage variables for Secret VRF, saves around 10,000+ in gas per TX. 
    //Since contract is upgradeable, we can update these values as well with it.

    //Core Routing
    bytes32 immutable chain_id_1; bytes32 immutable chain_id_2; 
    bytes32 immutable chain_id_3; uint256 immutable chain_id_length; 
    //string constant public task_destination_network = "secret-4";
    //address constant public secret_gateway_signer_address = 0x88e43F4016f8282Ea6235aC069D02BA1cE5417aB;
    string constant public task_destination_network = "pulsar-3";
    address constant public secret_gateway_signer_address = 0x2821E794B01ABF0cE2DA0ca171A1fAc68FaDCa06;

    //Secret VRF additions
    //string constant public VRF_routing_info = "secret16pcjalfuy72r4k26r4kn5f5x64ruzv30knflwx";
    string constant public VRF_routing_info = "secret1fxs74g8tltrngq3utldtxu9yys5tje8dzdvghr";

    string constant public VRF_routing_code_hash = "49ffed0df451622ac1865710380c14d4af98dca2d32342bb20f2b22faca3d00d";
    bytes constant VRF_info = abi.encodePacked('}","routing_info":"',VRF_routing_info,'","routing_code_hash":"',VRF_routing_code_hash,'","user_address":"0x0000","user_key":"AAA=","callback_address":"');


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

    /// @dev Task ID => Task
    mapping(uint256 => Task) public tasks;

    /*//////////////////////////////////////////////////////////////
                              Helpers
    //////////////////////////////////////////////////////////////*/

   function ethSignedPayloadHash(bytes memory payload) private pure returns (bytes32 payloadHash) {
        assembly {
            // Take scratch memory for the data to hash
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
            mstore(m, _signedMessageHash) // Store _signedMessageHash at memory location m
            mstore(add(m, 32), byte(0, calldataload(add(_signature.offset, 64)))) // Load v from _signature and store at m + 32
            mstore(add(m, 64), calldataload(add(_signature.offset, 0))) // Load r from _signature and store at m + 64
            mstore(add(m, 96), calldataload(add(_signature.offset, 32))) // Load s from _signature and store at m + 96
            // Call ecrecover: returns 0 on error, address on success, 0 for failure
            if iszero(staticcall(gas(), 0x01, m, 128, m, 32)) {
                revert(0, 0)
            }
            //load result into result
            signerAddress := mload(m) 
            mstore(0x40, add(m, 128)) // Update free memory pointer
        }
    }

    /// @notice Encodes a bytes memory array into a Base64 string
    /// @param data The address data to encode
    /// @return result The bytes28 encoded string

    function encodeAddressToBase64(address data) private pure returns (bytes28 result) {
        bytes memory table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        assembly {
            let resultPtr := mload(0x00) // Load scratch memory pointer
            table := add(table, 1)
            mstore8(resultPtr, mload(add(table, shr(154, data))))
            mstore8(add(resultPtr, 1), mload(add(table, and(shr(148, data), 0x3F))))
            mstore8(add(resultPtr, 2), mload(add(table, and(shr(142, data), 0x3F))))
            mstore8(add(resultPtr, 3), mload(add(table, and(shr(136, data), 0x3F))))
            mstore8(add(resultPtr, 4), mload(add(table, and(shr(130, data), 0x3F))))
            mstore8(add(resultPtr, 5), mload(add(table, and(shr(124, data), 0x3F))))
            mstore8(add(resultPtr, 6), mload(add(table, and(shr(118, data), 0x3F))))
            mstore8(add(resultPtr, 7), mload(add(table, and(shr(112, data), 0x3F))))
            mstore8(add(resultPtr, 8), mload(add(table, and(shr(106, data), 0x3F))))
            mstore8(add(resultPtr, 9), mload(add(table, and(shr(100, data), 0x3F))))
            mstore8(add(resultPtr, 10), mload(add(table, and(shr(94, data), 0x3F))))
            mstore8(add(resultPtr, 11), mload(add(table, and(shr(88, data), 0x3F))))
            mstore8(add(resultPtr, 12), mload(add(table, and(shr(82, data), 0x3F))))
            mstore8(add(resultPtr, 13), mload(add(table, and(shr(76, data), 0x3F))))
            mstore8(add(resultPtr, 14), mload(add(table, and(shr(70, data), 0x3F))))
            mstore8(add(resultPtr, 15), mload(add(table, and(shr(64, data), 0x3F))))
            mstore8(add(resultPtr, 16), mload(add(table, and(shr(58, data), 0x3F))))
            mstore8(add(resultPtr, 17), mload(add(table, and(shr(52, data), 0x3F))))
            mstore8(add(resultPtr, 18), mload(add(table, and(shr(46, data), 0x3F))))
            mstore8(add(resultPtr, 19), mload(add(table, and(shr(40, data), 0x3F))))
            mstore8(add(resultPtr, 20), mload(add(table, and(shr(34, data), 0x3F)))) 
            mstore8(add(resultPtr, 21), mload(add(table, and(shr(28, data), 0x3F))))
            mstore8(add(resultPtr, 22), mload(add(table, and(shr(22, data), 0x3F))))
            mstore8(add(resultPtr, 23), mload(add(table, and(shr(16, data), 0x3F))))
            mstore8(add(resultPtr, 24), mload(add(table, and(shr(10, data), 0x3F))))
            mstore8(add(resultPtr, 25), mload(add(table, and(shr(4, data), 0x3F))))
            mstore8(add(resultPtr, 26), mload(add(table, and(shl(2, data), 0x3F))))
            mstore8(add(resultPtr, 27), 0x3d)
            result := mload(resultPtr)
        }
    }


    /// @notice Converts a uint256 value into its string representation
    /// @param x The uint256 value to convert
    /// @return s The bytes string representation of the uint256 value

    function uint256toBytesString(uint256 x) private pure returns (bytes memory s) {
        unchecked {
            if (x < 1e31) { 
                uint256 c1 = itoa31(x);
                assembly {
                    s := mload(0x40) // Set s to point to the free memory pointer
                    let z := shr(248, c1) // Extract the digit count for c1
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
                    let z := shr(248, c3) // Extract the digit count for c3
                    mstore(s, add(z, 62)) // Allocate 32 bytes for the string length
                    mstore(add(s, 32), shl(sub(256, mul(z, 8)), c3)) // Store c3 adjusted by z digits
                    mstore(add(s, add(32, z)), shl(8, c2)) // Store the last 31 bytes of c2 starting at z bytes
                    mstore(add(s, add(63, z)), shl(8, c1)) // Store the last 31 bytes of c3 starting at z + 31 bytes
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
                //Core principle: last byte contains the mantissa of the number
                //first 31 bytes contain the converted number. 
                //Start with 0x30 byte offset, then add the number on it. 
                //0x30 + the number = the byte in hex that represents that number
                y = 0x0030303030303030303030303030303030303030303030303030303030303030
                    // Convert the number into ASCII digits and place them in the correct position
                    + (x % 10)
                    + ((x / 1e1 % 10) << 8);

                // Use checkpoints to reduce unnecessary divisions and modulo operations
                if (x < 1e3) {
                    if (x >= 1e2) return y += ((x * 0x290) & (0xf << 16)) | (3 << 248); // Three digits
                    if (x >= 1e1) return y += 2 << 248; // Two digits
                    return y += 1 << 248; // One digit
                }

                y +=  ((x / 1e2 % 10) << 16)
                    + ((x / 1e3 % 10) << 24)
                    + ((x / 1e4 % 10) << 32);

                if (x < 1e6) {
                    if (x >= 1e5) return y += ((x * 0xa7c5ad) & (0xf << 40)) | (6 << 248); // Six digits
                    if (x >= 1e4) return y += 5 << 248; // Five digits
                    return y += 4 << 248; // Four digits
                }

                y +=  ((x / 1e5 % 10) << 40)
                    + ((x / 1e6 % 10) << 48)
                    + ((x / 1e7 % 10) << 56);

                if (x < 1e9) {
                    if (x >= 1e8) return y += ((x * 0x2af31dc462) & (0xf << 64)) | (9 << 248); // Nine digits
                    if (x >= 1e7) return y += 8 << 248; // Eight digits
                    return y += 7 << 248; // Seven digits
                }

                y +=  ((x / 1e8 % 10) << 64)
                    + ((x / 1e9 % 10) << 72)
                    + ((x / 1e10 % 10) << 80);

                if (x < 1e12) {
                    if (x >= 1e11) return y += ((x * 0xafebff0bcb24b) & (0xf << 88)) | (12 << 248); // Twelve digits
                    if (x >= 1e10) return y += 11 << 248; // Eleven digits
                    return y += 10 << 248; // Ten digits
                }

                y +=  ((x / 1e11 % 10) << 88)
                    + ((x / 1e12 % 10) << 96)
                    + ((x / 1e13 % 10) << 104);

                if (x < 1e15) {
                    if (x >= 1e14) return y += ((x * 0x2d09370d42573603e) & (0xf << 112)) | (15 << 248); // Fifteen digits
                    if (x >= 1e13) return y += 14 << 248; // Fourteen digits
                    return y += 13 << 248; // Thirteen digits
                }

                y +=  ((x / 1e14 % 10) << 112)
                    + ((x / 1e15 % 10) << 120)
                    + ((x / 1e16 % 10) << 128);

                if (x < 1e18) {
                    if (x >= 1e17) return y += ((x * 0xb877aa3236a4b44909bf) & (0xf << 136)) | (18 << 248); // Eighteen digits
                    if (x >= 1e16) return y += 17 << 248; // Seventeen digits
                    return y += 16 << 248; // Sixteen digits
                }

                y +=  ((x / 1e17 % 10) << 136)
                    + ((x / 1e18 % 10) << 144)
                    + ((x / 1e19 % 10) << 152);

                if (x < 1e21) {
                    if (x >= 1e20) return y += ((x * 0x2f394219248446baa23d2ec8) & (0xf << 160)) | (21 << 248); // Twenty-one digits
                    if (x >= 1e19) return y += 20 << 248; // Twenty digits
                    return y += 19 << 248; // Nineteen digits
                }

                y +=  ((x / 1e20 % 10) << 160)
                    + ((x / 1e21 % 10) << 168)
                    + ((x / 1e22 % 10) << 176);

                if (x < 1e24) {
                    if (x >= 1e23) return y += ((x * 0xc16d9a0095928a2775b7053c0f2) & (0xf << 184)) | (24 << 248); // Twenty-four digits
                    if (x >= 1e22) return y += 23 << 248; // Twenty-three digits
                    return y += 22 << 248; // Twenty-two digits
                }

                y +=  ((x / 1e23 % 10) << 184)
                    + ((x / 1e24 % 10) << 192)
                    + ((x / 1e25 % 10) << 200);

                if (x < 1e27) {
                    if (x >= 1e26) return y += ((x * 0x318481895d962776a54d92bf80caa07) & (0xf << 208)) | (27 << 248); // Twenty-seven digits
                    if (x >= 1e25) return y += 26 << 248; // Twenty-six digits
                    return y += 25 << 248; // Twenty-five digits
                }

                y +=  ((x / 1e26 % 10) << 208)
                    + ((x / 1e27 % 10) << 216)
                    + ((x / 1e28 % 10) << 224);

                if (x < 1e30) {
                    if (x >= 1e29) return y += ((x * 0xcad2f7f5359a3b3e096ee45813a0433060) & (0xf << 232)) | (30 << 248); // Thirty digits
                    if (x >= 1e28) return y += 29 << 248; // Twenty-nine digits
                    else return y += 28 << 248; // Twenty-eight digits
                }

                y +=  ((x / 1e29 % 10) << 232)
                    + ((x / 1e30 % 10) << 240); 

                return y += 31 << 248; // Thirty-one digits
            }
    }

    function getChainId(bytes32 chain_id_1_tmp, bytes32 chain_id_2_tmp, bytes32 chain_id_3_tmp, uint256 chain_id_length_tmp) private pure returns (string memory result) {
        assembly {
            result := mload(0x40)
            mstore(result, chain_id_length_tmp)
            mstore(add(result, 32), chain_id_1_tmp)
            mstore(add(result, 64), chain_id_2_tmp)
            mstore(add(result, 96), chain_id_3_tmp)
            mstore(0x40, add(result, 128))
        }
    }
    
    /// @notice Converts a bytes memory array to an array of uint256
    /// @param data The bytes memory data to convert
    /// @return result The calldata for the returned Randomness
    
    function prepareRandomnessBytesToCallbackData(bytes4 callback_selector, uint256 requestId, bytes calldata data) private pure returns (bytes memory result) {
        require(data.length % 32 == 0, "Invalid Bytes Length");

        assembly {
            result := mload(0x40) 
            mstore(result, add(100, data.length))
            mstore(add(result, 32), callback_selector)
            mstore(add(result, 36), requestId)
            mstore(add(result, 68), 0x40)
            mstore(add(result, 100), div(data.length, 32)) 
            calldatacopy(add(result, 132), data.offset, data.length)
            mstore(0x40, add(add(result, 132), data.length))
        }
    }

    /// @notice Converts a bytes memory array into a callback data array
    /// @param data The bytes memory data to convert
    /// @return result The calldata for the returned data

    function prepareResultBytesToCallbackData(bytes4 callback_selector, uint256 _taskId, bytes calldata data) private pure returns (bytes memory result) {
        assembly {
            result := mload(0x40) 
            mstore(result, add(100, data.length))
            mstore(add(result, 32), callback_selector)
            mstore(add(result, 36), _taskId)
            mstore(add(result, 68), 0x40)
            mstore(add(result, 100), data.length) 
            calldatacopy(add(result, 132), data.offset, data.length)
            mstore(0x40, add(add(result, 132), data.length))
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
    event FulfilledRandomWords(uint256 indexed requestId);

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
        //Burn in the Chain-ID into the byte code into chain_id_1, chain_id_2 and chain_id_3 and chain_id_length. 
        bytes memory chain_id = uint256toBytesString(block.chainid);
        bytes32 chain_id_1_tmp; bytes32 chain_id_2_tmp; bytes32 chain_id_3_tmp; 
        uint256 chain_id_length_tmp = chain_id.length;

        assembly {
            chain_id_1_tmp := mload(add(chain_id, 32))
            if gt(chain_id_length_tmp, 32) {
                chain_id_2_tmp := mload(add(chain_id, 64))
                if gt(chain_id_length_tmp, 64) {
                    chain_id_3_tmp := mload(add(chain_id, 96))
                }  
            }
        }

        chain_id_1 = chain_id_1_tmp; 
        chain_id_2 = chain_id_2_tmp;
        chain_id_3 = chain_id_3_tmp;
        chain_id_length = chain_id.length;
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
        external payable returns (uint256 _taskId) {

        _taskId = taskId;
        
        uint256 estimatedPrice = estimateRequestPrice(_info.callback_gas_limit);

        // Refund any excess gas paid beyond the estimated price
        if (msg.value > estimatedPrice) {
            payable(tx.origin).transfer(msg.value - estimatedPrice);
        } else {
            // If not enough gas was paid, revert the transaction
            require(msg.value >= estimatedPrice, "Paid Callback Fee Too Low");
        }

        // Payload hash verification
        require(ethSignedPayloadHash(_info.payload) == _payloadHash, "Invalid Payload Hash");
        
        // persisting the task
        tasks[_taskId] = Task(bytes31(_payloadHash), false);

        //emit the task to be picked up by the relayer
        emit logNewTask(
            _taskId,
            getChainId(chain_id_1, chain_id_2, chain_id_3, chain_id_length),
            _userAddress,
            _routingInfo,
            _payloadHash,
            _info
        );

        //Increase the taskId to be used in the next gateway call. 
	    taskId = _taskId + 1;
    }

    struct Payload {
                bytes data; 
                string routing_info; 
                string routing_code_hash;
                address user_address;
                bytes user_key;
                address callback_address;
                bytes4 callback_selector; 
                uint32 callback_gas_limit;
    }

    /// @notice Requests random words for VRF
    /// @param _numWords The number of random words requested
    /// @param _callbackGasLimit The gas limit for the callback
    /// @return requestId The request ID for the random words

    function requestRandomness(
        uint32 _numWords,
        uint32 _callbackGasLimit
    ) external payable returns (uint256 requestId) {

        requestId = taskId;

        //Set limit on how many random words can be requested
        require(_numWords <= 2000, "Too Many random words Requested");

        uint256 estimatedPrice = estimateRequestPrice(_callbackGasLimit);

        // Refund any excess gas paid beyond the estimated price
        if (msg.value > estimatedPrice) {
            payable(tx.origin).transfer(msg.value - estimatedPrice);
        } else {
            // If not enough gas was paid, revert the transaction
            require(msg.value >= estimatedPrice, "Paid Callback Fee Too Low");
        }

        //construct the payload that is sent into the Secret Gateway
        /* bytes memory payload = bytes.concat(
            '{"data":"{\\"numWords\\":',
            uint256toBytesString(_numWords),
            VRF_info,
            encodeAddressToBase64(msg.sender), //callback_address
            '","callback_selector":"OLpGFA==","callback_gas_limit":', // 0x38ba4614 hex value already converted into base64, callback_selector of the fullfillRandomWords function
            uint256toBytesString(_callbackGasLimit),
            '}' 
        ); */

        bytes memory emptyBytes = hex"0000";

        Payload memory payloadStruct = Payload({
                data: abi.encodePacked('{\\"numWords\\":',uint256toBytesString(_numWords),'}"'),
                routing_info: VRF_routing_info, 
                routing_code_hash: VRF_routing_code_hash,
                user_address: 0x0000000000000000000000000000000000000000,
                user_key: emptyBytes,
                callback_address: msg.sender,
                callback_selector: 0x38ba4614,
                callback_gas_limit: _callbackGasLimit
        });
        
        bytes memory payload = abi.encode(payloadStruct);
         
        //generate the payload hash using the ethereum hash format for messages
        bytes32 payloadHash = ethSignedPayloadHash(payload);

        // ExecutionInfo struct
        ExecutionInfo memory executionInfo = ExecutionInfo({
            user_key: emptyBytes, // equals AAA= in base64
            user_pubkey: emptyBytes, // Fill with 0 bytes
            routing_code_hash: VRF_routing_code_hash, //RNG Contract codehash on Secret 
            task_destination_network: task_destination_network,
            handle: "request_random",
            nonce: bytes12(0),
            callback_gas_limit: _callbackGasLimit,
            payload: payload,
            payload_signature: emptyBytes // empty signature, fill with 0 bytes
        });

        // persisting the task
        tasks[requestId] = Task(bytes31(payloadHash), false);

        //emit the task to be picked up by the relayer
        emit logNewTask(
            requestId,
            getChainId(chain_id_1, chain_id_2, chain_id_3, chain_id_length),
            tx.origin,
            VRF_routing_info, //RNG Contract address on Secret 
            payloadHash,
            executionInfo
        );

        //Output the current task_id / request_id to the user and increase the taskId to be used in the next gateway call. 
        taskId = requestId + 1;
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
        require(bytes31(_info.payload_hash) == task.payload_hash_reduced, "Invalid Payload Hash");

        // Concatenate packet data elements
        bytes memory data = bytes.concat(
            bytes(_sourceNetwork),
            bytes(getChainId(chain_id_1, chain_id_2, chain_id_3, chain_id_length)),
            uint256toBytesString(_taskId),
            _info.payload_hash,
            _info.result,
            _info.callback_address,
            _info.callback_selector
        );
        
        // Perform Keccak256 + sha256 hash
        bytes32 packetHash = sha256(bytes.concat(keccak256(data)));

        //For EVM Chains that don't support the sha256 precompile
        //bytes32 packetHash = hashSHA256(keccak256(data));

        // Packet hash verification
        require(packetHash == _info.packet_hash, "Invalid Packet Hash");

        // Packet signature verification
        require(recoverSigner(packetHash, _info.packet_signature) == secret_gateway_signer_address, "Invalid Packet Signature");
        
        //Mark the task as completed
        tasks[_taskId].completed = true;

        // Continue with the function execution

        // Additional conversion for Secret VRF into uint256[] if callback_selector matches the fullfillRandomWords selector.
        bool callbackSuccessful; 
        if (_info.callback_selector == 0x38ba4614) {
            (callbackSuccessful, ) = address(_info.callback_address).call(
                prepareRandomnessBytesToCallbackData(0x38ba4614, _taskId, _info.result));
            emit FulfilledRandomWords(_taskId);
        }
        else {
            (callbackSuccessful, ) = address(_info.callback_address).call(
                prepareResultBytesToCallbackData(_info.callback_selector, _taskId, _info.result));
        }
        emit TaskCompleted(_taskId, callbackSuccessful);
    }

    /*//////////////////////////////////////////////////////////////
                     New Functions for Upgradeability
    //////////////////////////////////////////////////////////////*/

    function upgradeHandler() public {

    }
}
