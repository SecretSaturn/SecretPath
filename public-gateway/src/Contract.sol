// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

contract Gateway {


    /// @notice thrown when the signature is invalid
    error InvalidSignature();


    /*//////////////////////////////////////////////////////////////
                           Signature Utils
    //////////////////////////////////////////////////////////////*/

    /// @notice Splitting signature util for recovery
    /// @param _sig The signature
    function splitSignature(bytes memory _sig)
        public
        pure
        returns (
            bytes32 r,
            bytes32 s,
            uint8 v
        )
    {
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
    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature)
        public
        pure
        returns (address)
    {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);

        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    /// @notice Hashes the encoded message hash
    /// @param _messageHash the message hash 
    function getEthSignedMessageHash(bytes32 _messageHash)
        public
        pure
        returns (bytes32)
    {
        /*
        Signature is produced by signing a keccak256 hash with the following format:
        "\x19Ethereum Signed Message\n" + len(msg) + msg
        */
        return
            keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash)
            );
    }


    /*//////////////////////////////////////////////////////////////
                             Constructor
    //////////////////////////////////////////////////////////////*/

    address private owner;

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

    address masterVerificationAddress;

    /// @notice Initialize the verification address
    /// @param _masterVerificationAddress The input address
    function initialize(address _masterVerificationAddress) public onlyOwner {
        masterVerificationAddress = _masterVerificationAddress;
    }

    /*//////////////////////////////////////////////////////////////
                             Update Routes
    //////////////////////////////////////////////////////////////*/

   /// @dev mapping of chain name string to the verification address
   mapping (string=>address) route; 


    /// @notice Updating the route
    /// @param _route Route name
    /// @param _verificationAddress Address corresponding to the route
    /// @param _signature Signed hashed inputs(_route + _verificationAddress)
    function updateRoute(
        string memory _route,
        address _verificationAddress,
        bytes memory _signature
    ) public onlyOwner {
        
        bytes32 routeHash = getRouteHash(_route, _verificationAddress);
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(routeHash);

        bool verifySig;
        verifySig = recoverSigner(ethSignedMessageHash, _signature) == masterVerificationAddress;

        if (!verifySig) revert InvalidSignature();

        route[_route] = _verificationAddress;

    }

    /// @notice Get the encoded hash of the inputs for signing
    /// @param _routeInput Route name
    /// @param _verificationAddressInput Address corresponding to the route
    function getRouteHash(
        string memory _routeInput,
        address _verificationAddressInput
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(_routeInput, _verificationAddressInput));
    }

    /*//////////////////////////////////////////////////////////////
                             Pre Execution
    //////////////////////////////////////////////////////////////*/

    /// @notice Pre-Execution
    /// @param _handle handle for routing
    /// @param _userAddress The address of the sender
    /// @param _sourceNetwork Source network of the message
    /// @param _routingInfo Where to go one pulled into the next gateway
    /// @param routingInfoSignature callback for the sorce destination
    /// @param _payload Payload (data + routing_info + user_address)
    /// @param _payloadSignature Payload Signature
    /// @param _packetSignature Signature of the whole above packet
    /// @param _taskId TaskID for the message
    function preExecution() public  {
       

    }

    /*//////////////////////////////////////////////////////////////
                             Post Execution
    //////////////////////////////////////////////////////////////*/

    /// @notice Post-Execution
    /// @param _outputs Outputs from the private execution
    /// @param _data task ID+input pair
    /// @param _signature signature of params
    /// @param _sourceNetwork
    function postExecution() public {


    }







}
