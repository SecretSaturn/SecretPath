// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import "openzeppelin-contracts/contracts/utils/Counters.sol";

contract Gateway {
    using Counters for Counters.Counter;

    /// @notice thrown when the signature is invalid
    error InvalidSignature();

    /*//////////////////////////////////////////////////////////////
                              Events
    //////////////////////////////////////////////////////////////*/

    event logNewTask(
        address _callbackAddressLog,
        bytes4 _callbackSelectorLog,
        address _userAddressLog,
        string _sourceNetworkLog,
        string _routingInfoLog,
        Signature _routingInfoSignatureLog,
        bytes _payloadLog,
        bytes32 _payloadHashLog,
        Signature _payloadSignatureLog,
        Signature _packetSignatureLog
    );

    event logCompletedTask(
        string _sourceNetworkLog,
        string _routingInfoLog,
        Signature _routingInfoSignatureLog,
        bytes _payloadLog,
        bytes32 _payloadHashLog,
        Signature _payloadSignatureLog,
        Signature _packetSignatureLog,
        uint256 _taskIdLog
    );

    /*//////////////////////////////////////////////////////////////
                              Task
    //////////////////////////////////////////////////////////////*/

    /// @notice Structured task for presistence
    /// @param callbackAddress contract address for callback
    /// @param callbackSelector function selector for computed callback
    /// @param userAddress The address of the sender
    /// @param sourceNetwork Source network of the message
    /// @param routingInfo Where to go one pulled into the next gateway
    /// @param completed  Task completion status
    struct Task {
        address callbackAddress;
        bytes4 callbackSelector;
        address userAddress;
        string sourceNetwork;
        string routingInfo;
        bool completed;
    }

    function newTask(
        address _callbackAddress,
        bytes4 _callbackSelector,
        address _userAddress,
        string memory _sourceNetwork,
        string memory _routingInfo
    )
        public
        pure
        returns (Task memory)
    {
        return Task(_callbackAddress, _callbackSelector, _userAddress, _sourceNetwork, _routingInfo, false);
    }

    /*//////////////////////////////////////////////////////////////
                           Signature Utils
    //////////////////////////////////////////////////////////////*/

    struct Signature {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

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
    function recoverSigner(bytes32 _ethSignedMessageHash, Signature memory _signature) public pure returns (address) {
        // (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);

        return ecrecover(_ethSignedMessageHash, _signature.v, _signature.r, _signature.s);
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
    function updateRoute(string memory _route, address _verificationAddress, Signature memory _signature) public onlyOwner {
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
    mapping(uint256 => Task) private tasks;

    /// @notice Pre-Execution
    /// @param _callbackAddress contract address for callback
    /// @param _callbackSelector function selector for computed callback
    /// @param _userAddress The address of the sender
    /// @param _sourceNetwork Source network of the message
    /// @param _routingInfo Where to go one pulled into the next gateway
    /// @param _routingInfoSignature Signed hash of _routingInfo
    /// @param _payload Encrypted (data + routing_info + user_address)
    /// @param _payloadHash hash of _payload
    /// @param _payloadSignature Payload Signature
    /// @param _packetSignature Signature of the whole above packet
    function preExecution(
        address _callbackAddress,
        bytes4 _callbackSelector,
        address _userAddress,
        string memory _sourceNetwork,
        string memory _routingInfo,
        Signature memory _routingInfoSignature,
        bytes memory _payload,
        bytes32 _payloadHash,
        Signature memory _payloadSignature,
        Signature memory _packetSignature
    )
        public
    {
        bytes32 tempHash;
        bytes32 tempSignedEthMessageHash;
        bool verifySig;

        // Route info signature verification
        tempHash = getRouteInfoHash(_routingInfo);
        tempSignedEthMessageHash = getEthSignedMessageHash(tempHash);

        verifySig = true;
        verifySig = recoverSigner(tempSignedEthMessageHash, _routingInfoSignature) == _userAddress;
        if (!verifySig) {
            revert InvalidSignature();
        }

        // Payload hash signature verification
        verifySig = true;
        verifySig = recoverSigner(_payloadHash, _payloadSignature) == _userAddress;
        if (!verifySig) {
            revert InvalidSignature();
        }

        // Packet signature verification
        tempHash = getPacketHash(
            _callbackAddress,
            _callbackSelector,
            _userAddress,
            _sourceNetwork,
            _routingInfo,
            _routingInfoSignature,
            _payload,
            _payloadHash,
            _payloadSignature
        );
        tempSignedEthMessageHash = getEthSignedMessageHash(tempHash);

        verifySig = true;
        verifySig = recoverSigner(tempSignedEthMessageHash, _packetSignature) == _userAddress;
        if (!verifySig) {
            revert InvalidSignature();
        }

        // Creating the task
        Task memory task;
        task = newTask(_callbackAddress, _callbackSelector, _userAddress, _sourceNetwork, _routingInfo);

        // Incrementing the ID and persisting the task
        taskIds.increment();
        uint256 taskId = taskIds.current();
        tasks[taskId] = task;

        emit logNewTask(
            _callbackAddress,
            _callbackSelector,
            _userAddress,
            _sourceNetwork,
            _routingInfo,
            _routingInfoSignature,
            _payload,
            _payloadHash,
            _payloadSignature,
            _packetSignature
            );
    }

    /// @notice Get the encoded hash of the inputs for signing
    /// @param _routingInfo Routing Info
    function getRouteInfoHash(string memory _routingInfo) public pure returns (bytes32) {
        return keccak256(abi.encode(_routingInfo));
    }

    /// @notice Get the encoded hash of the whole packet
    function getPacketHash(
        address _callbackAddress,
        bytes4 _callbackSelector,
        address _userAddress,
        string memory _sourceNetwork,
        string memory _routingInfo,
        Signature memory _routingInfoSignature,
        bytes memory _payload,
        bytes32 _payloadHash,
        Signature memory _payloadSignature
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
                _sourceNetwork,
                _routingInfo,
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
    /// @param _packetSignature Signature of the whole above packet
    /// @param _taskId TaskId for the transmission of the message
    function postExecution(
        string memory _sourceNetwork,
        string memory _routingInfo,
        Signature memory _routingInfoSignature,
        bytes memory _payload,
        bytes32 _payloadHash,
        Signature memory _payloadSignature,
        Signature memory _packetSignature,
        uint256 _taskId
    )
        public
    {
        address checkerAddress = route[_sourceNetwork];

        // Route info signature verification
        bytes32 routeInfoHash = getRouteInfoHash(_routingInfo);
        bytes32 routeInfoEthSignedMessageHash = getEthSignedMessageHash(routeInfoHash);

        bool verifyRouteInfoSig;
        verifyRouteInfoSig = recoverSigner(routeInfoEthSignedMessageHash, _routingInfoSignature) == checkerAddress;

        if (!verifyRouteInfoSig) {
            revert InvalidSignature();
        }

        // Payload hash signature verification
        bool verifyPayloadHashSig;
        verifyPayloadHashSig = recoverSigner(_payloadHash, _payloadSignature) == checkerAddress;
        if (!verifyPayloadHashSig) {
            revert InvalidSignature();
        }

        (bool val,) = address(tasks[_taskId].callbackAddress).call(abi.encodeWithSelector(tasks[_taskId].callbackSelector, _payload));
        require(val == true, "Callback error");

        tasks[_taskId].completed = true;

        emit logCompletedTask(
            _sourceNetwork, _routingInfo, _routingInfoSignature, _payload, _payloadHash, _payloadSignature, _packetSignature, _taskId
            );
    }
}