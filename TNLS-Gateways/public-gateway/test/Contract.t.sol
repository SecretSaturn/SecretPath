// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "forge-std/console2.sol";
import {Gateway} from "../src/Gateway.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract ContractTest is Test {
    /*//////////////////////////////////////////////////////////////
                                SETUP
    //////////////////////////////////////////////////////////////*/

    Gateway internal gateway;
    address deployer;
    address gatewayOwner;
    address notOwner;
    ProxyAdmin proxyAdmin;
    TransparentUpgradeableProxy gatewayProxy;

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

    event ComputedResult(uint256 indexed taskId, bytes result);

    function setUp() public {
        deployer = vm.addr(3);
        gatewayOwner = vm.addr(9);
        notOwner = vm.addr(4);
        vm.prank(deployer);
        // Deploy ProxyAdmin
        proxyAdmin = new ProxyAdmin(msg.sender);

        // Deploy Gateway Logic Contract
        Gateway gatewayLogic = new Gateway();

        // Prepare initializer data for Gateway
        bytes memory initializerData = abi.encodeWithSelector(
            Gateway.initialize.selector
        );
        
        vm.prank(gatewayOwner);
        // Deploy TransparentUpgradeableProxy
        gatewayProxy = new TransparentUpgradeableProxy(
            address(gatewayLogic),
            address(proxyAdmin),
            initializerData
        );

        // Cast the proxy address to the Gateway interface
        gateway = Gateway(address(gatewayProxy));
    }

    /*//////////////////////////////////////////////////////////////
                    Helpers from Gateway Contract
    //////////////////////////////////////////////////////////////*/

    /// @notice Splitting signature util for recovery
    /// @param _sig The signature
    function splitSignature(bytes memory _sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
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

    function sliceLastByte(bytes32 data) private pure returns (bytes31) {
        return bytes31(data & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00);
    }

    /*//////////////////////////////////////////////////////////////
                           Helper Functions
    //////////////////////////////////////////////////////////////*/

    function getPayloadHash(bytes memory _payload) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_payload));
       // return keccak256(bytes.concat("\x19Ethereum Signed Message:\n", bytes32(_payload.length), _payload));
    }

    function getResultHash(bytes memory _result) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_result));
    }

    function getRouteInfoHash(string memory _routingInfo) public pure returns (bytes32) {
        return keccak256(abi.encode(_routingInfo));
    }

    function getRoutingInfoSignature(string memory _routingInfo, uint256 _foundryPkey) public returns (bytes memory) {
        bytes32 routeHash = getRouteInfoHash(_routingInfo);
        bytes32 routeEthSignedMessageHash = getEthSignedMessageHash(routeHash);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(_foundryPkey, routeEthSignedMessageHash);
        bytes memory routingInfoSig = abi.encodePacked(r1, s1, v1);

        return routingInfoSig;
    }

    function getPayloadSignature(bytes memory _payload, uint256 _foundryPkey) public returns (bytes memory) {
        bytes32 payloadHash = getPayloadHash(_payload);
        bytes32 payloadEthSignedMessageHash = getEthSignedMessageHash(payloadHash);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(_foundryPkey, payloadEthSignedMessageHash);
        bytes memory payloadSig = abi.encodePacked(r2, s2, v2);

        return payloadSig;
    }

    function getPacketSignature(bytes32 _packetHash, uint256 _foundryPkey) public returns (bytes memory) {
        bytes32 packetEthSignedMessageHash = getEthSignedMessageHash(_packetHash);
        (uint8 v3, bytes32 r3, bytes32 s3) = vm.sign(_foundryPkey, packetEthSignedMessageHash);
        bytes memory packetSig = abi.encodePacked(r3, s3, v3);

        return packetSig;
    }

    function getResultSignature(bytes memory _result, uint256 _foundryPkey) public returns (bytes memory) {
        bytes32 resultHash = getResultHash(_result);
        bytes32 resultEthSignedMessageHash = getEthSignedMessageHash(resultHash);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(_foundryPkey, resultEthSignedMessageHash);
        bytes memory resultSig = abi.encodePacked(r2, s2, v2);

        return resultSig;
    }

    /*//////////////////////////////////////////////////////////////
                           Test Cases
    //////////////////////////////////////////////////////////////*/


    function test_PreExecution() public {
        // USER ADDRESS       ----->   vm.addr(5);
        // CALLBACK ADDRESS   ----->   vm.addr(7);

        string memory routingInfo = "secret";

        // bytes32 string encoding of "add a bunch of stuff"
        bytes memory payload = hex"61646420612062756e6368206f66207374756666000000000000000000000000";
        bytes32 payloadHash = getPayloadHash(payload);
        payloadHash = getEthSignedMessageHash(payloadHash);

        // encoding bytes of "some public key"
        bytes memory userKey = hex"736f6d65207075626c6963206b65790000000000000000000000000000000000";
        bytes memory userPublicKey = hex"040b8d42640a7eded641dd42ad91d7c9ae3644a2412bdff174790012774e5528a30f9f0a630977d53e7a862eb2fb89207fe4fafc824992d281ba0180c6a1fddb4c";

        Gateway.ExecutionInfo memory assembledInfo = Gateway.ExecutionInfo({
            user_key: userKey,
            user_pubkey:userPublicKey,
            routing_code_hash: "some RoutingCodeHash",
            task_destination_network: "pulsar-3",
            handle: "some kinda handle",
            nonce: "ssssssssssss",
            payload: payload,
            payload_signature: getPayloadSignature(payload, 5)
        });

        gateway.send(payloadHash, vm.addr(5), routingInfo, assembledInfo);

        (bytes31 tempPayloadHash,) = gateway.tasks(1);
        assertEq(tempPayloadHash, sliceLastByte(payloadHash), "payloadHash failed");

        (,bool tempCompleted) = gateway.tasks(1);
        assertEq(tempCompleted, false, "tempCompleted failed");
    }

    function testFail_CannotPreExecutionWithoutValidPayloadSig() public {

        string memory routingInfo = "secret";

        // bytes32 string encoding of "add a bunch of stuff"
        bytes memory payload = hex"61646420612062756e6368206f66207374756666000000000000000000000000";
        bytes32 payloadHash = getPayloadHash(payload);
        payloadHash = getEthSignedMessageHash(payloadHash);

        // encoding bytes of "some public key"
        bytes memory userKey = hex"736f6d65207075626c6963206b65790000000000000000000000000000000000";
        bytes memory userPublicKey = hex"040b8d42640a7eded641dd42ad91d7c9ae3644a2412bdff174790012774e5528a30f9f0a630977d53e7a862eb2fb89207fe4fafc824992d281ba0180c6a1fddb4c";

        Gateway.ExecutionInfo memory assembledInfo = Gateway.ExecutionInfo({
            user_key: userKey,
            user_pubkey:userPublicKey,
            routing_code_hash: "some RoutingCodeHash",
            task_destination_network: "pulsar-3",
            handle: "some kinda handle",
            nonce: "ssssssssssss",
            payload: payload,
            payload_signature: getPayloadSignature(payload, 7)
        });

        gateway.send(payloadHash, vm.addr(5), routingInfo, assembledInfo);

        vm.expectRevert(abi.encodeWithSignature("InvalidSignature()"));
    }

    function test_PostExecution() public {
                vm.chainId(11155111); 
        string memory sourceNetwork = "secret";
    
        uint256 taskId = 1;

        // bytes32 string encoding of "add a bunch of stuff"
        bytes memory payload = hex"61646420612062756e6368206f66207374756666000000000000000000000000";
        bytes32 payloadHash = getPayloadHash(payload);
        payloadHash = getEthSignedMessageHash(payloadHash);

        // bytes32 string encoding of "some result"
        bytes memory result = hex"736f6d6520726573756c74000000000000000000000000000000000000000000";
        bytes32 resultHash = getResultHash(result);
        resultHash = getEthSignedMessageHash(resultHash);

        Gateway.PostExecutionInfo memory assembledInfo = Gateway.PostExecutionInfo({
            payload_hash: payloadHash,
            result: result,
            packet_hash: resultHash,
            packet_signature: getResultSignature(result, 2),
            callback_address: bytes20(address(gateway)),
            callback_selector: hex"faef40fe",
            callback_gas_limit: bytes4(uint32(300000))
        });

        gateway.postExecution(taskId, sourceNetwork, assembledInfo);

        (,bool tempCompleted) = gateway.tasks(1);
        assertEq(tempCompleted, true);
    }

    function testFail_PostExecutionWithoutMapStoredAddressSignatures() public {
        test_PreExecution();

        string memory sourceNetwork = "secret";
        uint256 taskId = 1;

        // bytes32 string encoding of "add a bunch of stuff"
        bytes memory payload = hex"61646420612062756e6368206f66207374756666000000000000000000000000";
        bytes32 payloadHash = getPayloadHash(payload);
        payloadHash = getEthSignedMessageHash(payloadHash);

        // bytes32 string encoding of "some result"
        bytes memory result = hex"736f6d6520726573756c74000000000000000000000000000000000000000000";
        bytes32 resultHash = getResultHash(result);
        resultHash = getEthSignedMessageHash(resultHash);

        Gateway.PostExecutionInfo memory assembledInfo = Gateway.PostExecutionInfo({
            payload_hash: payloadHash,
            result: result,
            packet_hash: resultHash,
            packet_signature: getResultSignature(result, 6),
            callback_address: bytes20(address(gateway)),
            callback_selector: hex"faef40fe",
            callback_gas_limit: bytes4(uint32(300000))
        });

        gateway.postExecution(taskId, sourceNetwork, assembledInfo);

        vm.expectRevert(abi.encodeWithSignature("InvalidResultSignature()"));
    }

    /*//////////////////////////////////////////////////////////////
                      Stubbed Value Case Setup
    //////////////////////////////////////////////////////////////*/

    function test_PreExecutionSetupForExplicitCase() public {

        address userAddress = 0x50FcF0c327Ee4341313Dd5Cb987f0Cd289Be6D4D;

        string memory routingInfo = "secret";

        // bytes32 string encoding of "add a bunch of stuff"
        bytes memory payload = hex"0e9cff93bb71eb6eaabb1d64dba1841ba9202784af250812f7588a42c53d7ff1866cc2c682fd8968a2a36a9a7b5f1721c69d761a6bd4a26ef6b1c2f82cd35a7d29369fbeab8ad35c9ce162560e9a5cf2a271d30bb5b3e86206396bc6973f30ecb87959d5310688cb5283cf6eec57d86bb3c0bcd2d29d341d686f66208d90f65223cc988ce5b8923bed3225847ddc5859eef515ffb8ea77e8faafc891c2bcf8c1898ad53081367c052c866444536972c58672a1994cfc0ed174eea0ec7b324f2c4214c658fd75d06180e0984546a838559b890220d41d1ee4882f6371b7352c49f10ce45c360c4a98f9c5bf988bc49392ac005edb8c8683258163acb87e989dee647fcbf4e94b7bb320525c054dadad82764c34d82fa3b10bfd9edf260224eb86275f5ad390ce42fd423689cbe45f42350ed23465112554857d25f12a00f33e1c202cd419f512ad842f1fef95fa5bfd4898a810e9f0ab4354453aca9bb516c49c8a88bc1134cc8f2fa1d7e5cb65ff23ffbc7727d091c0b1e18c7c6647a49e3e951c2e8ec87ca3cdeb3bedb5d5b1650d4b622bfc3e6ca7c3d5afa6cbe4f0d80ac8dbd966359d";
        bytes32 payloadHash = hex"fa6ec6995359ca7c7ea6602443f212e8295b9407cfa9f1f04c4651df345453fa";
        bytes memory payloadSignature =
            hex"a6c728c5307ec4a84f15805f55d3827c6e58eb661fa5633956b500540e6b0b376cba788ef8ad19024ecc5c769cdd917ae07423f0724709e10fce0e3d7510da7c1c";

        // encoding bytes of "some public key"
        bytes memory userKey = hex"736f6d65207075626c6963206b65790000000000000000000000000000000000";
        bytes memory userPublicKey = hex"040b8d42640a7eded641dd42ad91d7c9ae3644a2412bdff174790012774e5528a30f9f0a630977d53e7a862eb2fb89207fe4fafc824992d281ba0180c6a1fddb4c";

        Gateway.ExecutionInfo memory assembledInfo = Gateway.ExecutionInfo({
            user_key: userKey,
            user_pubkey:userPublicKey,
            routing_code_hash: "some RoutingCodeHash",
            task_destination_network: "pulsar-3",
            handle: "some kinda handle",
            nonce: "ssssssssssss",
            payload: payload,
            payload_signature: payloadSignature
        });

        gateway.send(payloadHash, userAddress,routingInfo, assembledInfo );

        (bytes31 tempPayloadHash,) = gateway.tasks(1);
        assertEq(tempPayloadHash, sliceLastByte(payloadHash));

        (,bool tempCompleted) = gateway.tasks(1);
        assertEq(tempCompleted, false);
    }

    function test_PostExecutionExplicitValues() public {
        test_PreExecutionSetupForExplicitCase();

        string memory sourceNetwork = "secret";
        uint256 taskId = 1;

        // callback
        bytes20 callback_address = hex"7b226d795f76616c7565223a327d";
        bytes4 callback_selector = hex"faef40fe";
        bytes4 callback_gas_limit = bytes4(uint32(300000));

        // payload
        bytes32 payloadHash = hex"fa6ec6995359ca7c7ea6602443f212e8295b9407cfa9f1f04c4651df345453fa";

        // result
        bytes memory result = hex"7b226d795f76616c7565223a327d";

        // packet
        bytes32 packetHash = hex"923b23c023d0e5e66ac122d9804414f4f9cab06d7a6ce6c4b8c586a1fa57264c";
        bytes memory packetSignature =
            hex"2db95ebb82b81f8240d952e1c6edf021e098de63d32f1f0d3bbbb7daf0e9edbd3378fc42e31d1041467c76388a35078968f1f6f2eb781b5b83054a1d90ba41ff1c";

        Gateway.PostExecutionInfo memory assembledInfo = Gateway.PostExecutionInfo({
            payload_hash: payloadHash,
            result: result,
            packet_hash: packetHash,
            packet_signature: packetSignature,
            callback_address: callback_address,
            callback_selector: callback_selector,
            callback_gas_limit: callback_gas_limit
        });

        gateway.postExecution(taskId, sourceNetwork, assembledInfo);

        (,bool tempCompleted) = gateway.tasks(1);
        assertEq(tempCompleted, true);
    }
}