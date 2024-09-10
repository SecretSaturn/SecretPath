// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

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
    address secretGatewaySigner;
    ProxyAdmin proxyAdmin;
    TransparentUpgradeableProxy gatewayProxy;

    function setUp() public {
        deployer = vm.addr(3);
        gatewayOwner = vm.addr(9);
        notOwner = vm.addr(4);
        secretGatewaySigner = vm.addr(6);

        vm.chainId(1); 
        vm.prank(deployer);

        // Deploy Gateway Logic Contract
        Gateway gatewayLogic = new Gateway(secretGatewaySigner);

        // Prepare initializer data for Gateway
        bytes memory initializerData = abi.encodeWithSelector(
            Gateway.initialize.selector
        );
        
        vm.prank(gatewayOwner);
        // Deploy TransparentUpgradeableProxy
        gatewayProxy = new TransparentUpgradeableProxy(
            address(gatewayLogic),
            msg.sender,
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
        return keccak256(bytes.concat("\x19Ethereum Signed Message:\n32", _messageHash));
    }

    /// @notice Get the encoded hash of the inputs for signing
    /// @param _routeInput Route name
    /// @param _verificationAddressInput Address corresponding to the route
    function getRouteHash(string memory _routeInput, address _verificationAddressInput) internal pure returns (bytes32) {
        return keccak256(abi.encode(_routeInput, _verificationAddressInput));
    }

    /*//////////////////////////////////////////////////////////////
                           Helper Functions
    //////////////////////////////////////////////////////////////*/

    function getPacketHash(bytes memory sourceNetwork, uint256 taskId, bytes32 payloadHash, bytes memory result, address callback_address, bytes4 callback_selector) public view returns (bytes32 packetHash) {
         // Concatenate packet data elements
        bytes memory data = bytes.concat(
            sourceNetwork,
            uint256toBytesString(block.chainid),
            uint256toBytesString(taskId),
            payloadHash,
            result,
            bytes20(callback_address),
            callback_selector
        );
        
        // Perform Keccak256 + sha256 hash
        packetHash = sha256(bytes.concat(keccak256(data)));
    }

    function uint256toBytesString(uint256 value) public pure returns (bytes memory buffer) {
        if (value == 0) {
            return "0";
        }
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
    }

    function getPayloadSignature(bytes memory _payload, uint256 _foundryPkey) public pure returns (bytes memory) {
        bytes32 payloadEthSignedMessageHash = getEthSignedMessageHash(keccak256(_payload));
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(_foundryPkey, payloadEthSignedMessageHash);
        bytes memory payloadSig = abi.encodePacked(r2, s2, v2);

        return payloadSig;
    }

    function getPacketSignature(bytes32 _packetHash, uint256 _foundryPkey) public pure returns (bytes memory) {
        (uint8 v3, bytes32 r3, bytes32 s3) = vm.sign(_foundryPkey, _packetHash);
        bytes memory packetSig = abi.encodePacked(r3, s3, v3);

        return packetSig;
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
        bytes32 payloadHash = getEthSignedMessageHash(keccak256(payload));

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
            callback_gas_limit: 300000,
            payload: payload,
            payload_signature: getPayloadSignature(payload, 5)
        });

        gateway.send(payloadHash, vm.addr(5), routingInfo, assembledInfo);

        (bytes31 tempPayloadHash,) = gateway.tasks(1);
        assertEq(tempPayloadHash, bytes31(payloadHash), "payloadHash failed");

        (,bool tempCompleted) = gateway.tasks(1);
        assertEq(tempCompleted, false, "tempCompleted failed");
    }

    function testFail_CannotPreExecutionWithoutValidPayloadSig() public {

        string memory routingInfo = "secret";

        // bytes32 string encoding of "add a bunch of stuff"
        bytes memory payload = hex"61646420612062756e6368206f66207374756666000000000000000000000000";
        bytes32 payloadHash = getEthSignedMessageHash(keccak256(payload));

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
            callback_gas_limit: 300000,
            payload: payload,
            payload_signature: getPayloadSignature(payload, 7)
        });

        gateway.send(payloadHash, vm.addr(5), routingInfo, assembledInfo);

        vm.expectRevert(abi.encodeWithSignature("InvalidSignature()"));
    }

    function test_PostExecution() public {
        test_PreExecution();
        string memory sourceNetwork = "secret";
    
        uint256 taskId = 1;

        // bytes32 string encoding of "add a bunch of stuff"
        bytes memory payload = hex"61646420612062756e6368206f66207374756666000000000000000000000000";
        bytes32 payloadHash = getEthSignedMessageHash(keccak256(payload));

        // bytes32 string encoding of "some result"
        bytes memory result = hex"736f6d6520726573756c74000000000000000000000000000000000000000000";
        bytes32 packetHash = getPacketHash(bytes(sourceNetwork), taskId, payloadHash, result, address(gateway), hex"faef40fe");
        bytes memory packetSignature = getPacketSignature(packetHash, 6);

        Gateway.PostExecutionInfo memory assembledInfo = Gateway.PostExecutionInfo({
            payload_hash: payloadHash,
            result: result,
            packet_hash: packetHash,
            packet_signature: packetSignature,
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
        bytes32 payloadHash = getEthSignedMessageHash(keccak256(payload));

        // bytes32 string encoding of "some result"
        bytes memory result = hex"736f6d6520726573756c74000000000000000000000000000000000000000000";
        bytes32 packetHash = getPacketHash(bytes(sourceNetwork), taskId, payloadHash, result, address(gateway), hex"faef40fe");
        bytes memory packetSignature = getPacketSignature(packetHash, 6);

        Gateway.PostExecutionInfo memory assembledInfo = Gateway.PostExecutionInfo({
            payload_hash: payloadHash,
            result: result,
            packet_hash: packetHash,
            packet_signature: packetSignature,
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

    function test_PostExecutionExplicitValues() public {
        vm.chainId(11155111); 
        vm.prank(deployer);

        // Deploy Gateway Logic Contract with signer address 0x2821E794B01ABF0cE2DA0ca171A1fAc68FaDCa06
        Gateway gatewayLogic = new Gateway(address(0x2821E794B01ABF0cE2DA0ca171A1fAc68FaDCa06));

        // Prepare initializer data for Gateway
        bytes memory initializerData = abi.encodeWithSelector(
            Gateway.initialize.selector
        );
        
        vm.prank(gatewayOwner);
        // Deploy TransparentUpgradeableProxy
        TransparentUpgradeableProxy gatewayProxyNew = new TransparentUpgradeableProxy(
            address(gatewayLogic),
            msg.sender,
            initializerData
        );

        // Cast the proxy address to the Gateway interface
        Gateway gatewayNew = Gateway(address(gatewayProxyNew));

        address userAddress = 0x50FcF0c327Ee4341313Dd5Cb987f0Cd289Be6D4D;

        uint256 taskId = 968;
        vm.store(address(gatewayNew), bytes32(uint256(0)), bytes32(uint256(taskId)));

        string memory routingInfo = "secret1aawazragzd7zlmn3ym09wuryhxn54x2846gd2v";

        // bytes32 string encoding of "add a bunch of stuff"
        bytes memory payload = hex"9fcc87a3acaae44bab74c4e4ea5c53438b5332a37c1435f1d6afb03a6c060d9cbf01de09d562888748751a213dfe8261112eac91997fa1e774853af3c6f02454fae85ab9dd7caa9e75cd27f0c57572e04724922c2b32dd157ce307bdd3ad8091d9c97a27d3a17ba9300e32735f93eb4e30ec5f1f0288628c5149220ee2ff5663eb1cf72bdf0251d570c39cd912bc618dc612e8ac8cede0f4d4cd5b14061b4d289960a02bd8aa832865749bde39b9adfa33eb09d44cd9e3953253158995019001e585f8661ddbed26d6b4a1898eba208a56b71f7a11e7fdc50414a12e63522e810691567138485aecb6af3ef4ee2f6d1469cdc8744efecace87276eda920ec425b68b4ccf8cdfe2af531c4d8c5f019e7566ee629b57f371f42746f2716b32dca16d95a4137c95fcda80ccde94d4acd84ff2ecc7abf2d87cac33abb571c026df6ab91b346f3a6dda3f9a0294b4be5d7e71a2adf8102fa3bf954da327bd2e0f981c13a8dff3b045c0ad948acbf16305e44910a36aa477e935a5628ab510d8b021f692cf5150d2c82af56c40ad97f6f7044242befe2bcfef3ec3732609128f18ed85d8186b871a8d686ea028f6b767681cb53d8ee48dec4605621bb59c0b01d0868a0e04803d24b19a4e25d1f7c9071e85";
        bytes32 payloadHash = hex"497a3b745cef16ffe10fe3412e0fdda0642f3e919b9a037ad7cceafcb28b658f";
        bytes memory payloadSignature =
            hex"c6d8dad66ff1309464660516d2d65d6e89218ceded094bb05f5085811a66c2f64304ad70a87c7002e09b07eabd75ffd464a777ae19f8359113c210a7212cc5021c";

        // encoding bytes of "some public key"
        bytes memory userKey = hex"035326b77c45a33eb9153dca33325358870b897416982028ae03a8b3a46f78b4d6";
        bytes memory userPublicKey = hex"048e368db756bc5f586c074851625a21593c21e6a6814820b545fe52b0e1466fc04154a3182d86e27b00f48857a427d985d29d8dfad936a434c1b01f0f0adcd6a0";

        Gateway.ExecutionInfo memory assembledInfo = Gateway.ExecutionInfo({
            user_key: userKey,
            user_pubkey:userPublicKey,
            routing_code_hash: "4f4054beb60d13c1fceece7be3ea7c349e46b70c1fbbf2517f713180d6033c84",
            task_destination_network: "pulsar-3",
            handle: "request_random",
            nonce: hex"086d58cf22336d92798128d4",
            callback_gas_limit: 90000,
            payload: payload,
            payload_signature: payloadSignature
        });

        gatewayNew.send(payloadHash, userAddress, routingInfo, assembledInfo );

        // result
        bytes memory result = hex"3238";

        // packet
        bytes32 packetHash = hex"79f6c82153147da3e7ec399229b41a1accbc7ad34620adcb96990087b9ac58f3";
        bytes memory packetSignature =
            hex"c51a532a75b9758c239b02d2f797236290db8b0a80a1a8a33ed889ceb0d9061a24c2cb463437b7c0fda60c560b2ba0e240fbda421182d5d0b30ebd609de1f1971b";

        Gateway.PostExecutionInfo memory assembledPostInfo = Gateway.PostExecutionInfo({
            payload_hash: payloadHash,
            result: result,
            packet_hash: packetHash,
            packet_signature: packetSignature,
            callback_address: hex"3879e146140b627a5c858a08e507b171d9e43139",
            callback_selector: hex"373d450c",
            callback_gas_limit: bytes4(uint32(90000))
        });

        gatewayNew.postExecution(taskId, "pulsar-3", assembledPostInfo);

        (,bool tempCompleted_2) = gatewayNew.tasks(taskId);
        assertEq(tempCompleted_2, true);
    }
}
