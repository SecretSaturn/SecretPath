// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "forge-std/console2.sol";
import {Gateway} from "../src/Gateway.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/utils/Base64.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

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
    function splitSignature(
        bytes memory _sig
    ) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
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
    function getEthSignedMessageHash(
        bytes32 _messageHash
    ) internal pure returns (bytes32) {
        /*
        Signature is produced by signing a keccak256 hash with the following format:
        "\x19Ethereum Signed Message\n" + len(msg) + msg
        */
        return
            keccak256(
                bytes.concat("\x19Ethereum Signed Message:\n32", _messageHash)
            );
    }

    /// @notice Get the encoded hash of the inputs for signing
    /// @param _routeInput Route name
    /// @param _verificationAddressInput Address corresponding to the route
    function getRouteHash(
        string memory _routeInput,
        address _verificationAddressInput
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(_routeInput, _verificationAddressInput));
    }

    /*//////////////////////////////////////////////////////////////
                               Helper Functions
    //////////////////////////////////////////////////////////////*/

    function getPacketHash(
        bytes memory sourceNetwork,
        uint256 taskId,
        bytes32 payloadHash,
        bytes memory result,
        address callback_address,
        bytes4 callback_selector
    ) public view returns (bytes32 packetHash) {
        // Concatenate packet data elements
        bytes memory data = bytes.concat(
            sourceNetwork,
            bytes(Strings.toString(block.chainid)),
            bytes(Strings.toString(taskId)),
            payloadHash,
            result,
            bytes20(callback_address),
            callback_selector
        );

        // Perform Keccak256 + sha256 hash
        packetHash = sha256(bytes.concat(keccak256(data)));
    }

    function getPayloadSignature(
        bytes memory _payload,
        uint256 _foundryPkey
    ) public pure returns (bytes memory) {
        bytes32 payloadEthSignedMessageHash = getEthSignedMessageHash(
            keccak256(_payload)
        );
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(
            _foundryPkey,
            payloadEthSignedMessageHash
        );
        bytes memory payloadSig = abi.encodePacked(r2, s2, v2);

        return payloadSig;
    }

    function getPacketSignature(
        bytes32 _packetHash,
        uint256 _foundryPkey
    ) public pure returns (bytes memory) {
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

        vm.prank(vm.addr(5), vm.addr(5));
        vm.deal(vm.addr(5), 1 ether);

        string memory sourceNetwork = "secret";
        string memory routingInfo = "secret";

        // bytes32 string encoding of "add a bunch of stuff"
        bytes
            memory payload = hex"61646420612062756e6368206f66207374756666000000000000000000000000";
        bytes32 payloadHash = getEthSignedMessageHash(keccak256(payload));

        // encoding bytes of "some public key"
        bytes
            memory userKey = hex"736f6d65207075626c6963206b65790000000000000000000000000000000000";
        bytes
            memory userPublicKey = hex"040b8d42640a7eded641dd42ad91d7c9ae3644a2412bdff174790012774e5528a30f9f0a630977d53e7a862eb2fb89207fe4fafc824992d281ba0180c6a1fddb4c";

        Gateway.ExecutionInfo memory assembledInfo = Gateway.ExecutionInfo({
            user_key: userKey,
            user_pubkey: userPublicKey,
            routing_code_hash: "some RoutingCodeHash",
            task_destination_network: sourceNetwork,
            handle: "some kinda handle",
            nonce: "ssssssssssss",
            callback_gas_limit: 300000,
            payload: payload,
            payload_signature: getPayloadSignature(payload, 5)
        });

        uint256 requestId = gateway.send{value: 0.5 ether}(
            payloadHash,
            vm.addr(5),
            routingInfo,
            assembledInfo
        );
        assertEq(requestId, 1, "requestId failed");

        (bytes31 tempPayloadHash, ) = gateway.tasks(1);
        assertEq(tempPayloadHash, bytes31(payloadHash), "payloadHash failed");

        (, bool tempCompleted) = gateway.tasks(1);
        assertEq(tempCompleted, false, "tempCompleted failed");
    }

    function test_PostExecution() public {
        test_PreExecution();
        string memory sourceNetwork = "secret";

        uint256 taskId = 1;

        // bytes32 string encoding of "add a bunch of stuff"
        bytes
            memory payload = hex"61646420612062756e6368206f66207374756666000000000000000000000000";
        bytes32 payloadHash = getEthSignedMessageHash(keccak256(payload));

        // bytes32 string encoding of "some result"
        bytes
            memory result = hex"736f6d6520726573756c74000000000000000000000000000000000000000000";
        bytes32 packetHash = getPacketHash(
            bytes(sourceNetwork),
            taskId,
            payloadHash,
            result,
            address(gateway),
            hex"373d450c"
        );
        bytes memory packetSignature = getPacketSignature(packetHash, 6);

        Gateway.PostExecutionInfo memory assembledInfo = Gateway
            .PostExecutionInfo({
                payload_hash: payloadHash,
                result: result,
                packet_hash: packetHash,
                packet_signature: packetSignature,
                callback_address: bytes20(address(gateway)),
                callback_selector: hex"373d450c",
                callback_gas_limit: bytes4(uint32(300000))
            });

        gateway.postExecution(taskId, sourceNetwork, assembledInfo);

        (, bool tempCompleted) = gateway.tasks(1);
        assertEq(tempCompleted, true);
    }

    function test_PostExecutionWithoutValidSignature() public {
        test_PreExecution();
        string memory sourceNetwork = "secret";

        uint256 taskId = 1;

        // bytes32 string encoding of "add a bunch of stuff"
        bytes
            memory payload = hex"61646420612062756e6368206f66207374756666000000000000000000000000";
        bytes32 payloadHash = getEthSignedMessageHash(keccak256(payload));

        // bytes32 string encoding of "some result"
        bytes
            memory result = hex"736f6d6520726573756c74000000000000000000000000000000000000000000";
        bytes32 packetHash = getPacketHash(
            bytes(sourceNetwork),
            taskId,
            payloadHash,
            result,
            address(gateway),
            hex"373d450c"
        );
        bytes memory packetSignature = getPacketSignature(packetHash, 4);

        Gateway.PostExecutionInfo memory assembledInfo = Gateway
            .PostExecutionInfo({
                payload_hash: payloadHash,
                result: result,
                packet_hash: packetHash,
                packet_signature: packetSignature,
                callback_address: bytes20(address(gateway)),
                callback_selector: hex"373d450c",
                callback_gas_limit: bytes4(uint32(300000))
            });

        vm.expectRevert("Invalid Packet Signature");
        gateway.postExecution(taskId, sourceNetwork, assembledInfo);
    }

    function test_RequestRandomness() public {
        vm.prank(vm.addr(5), vm.addr(5));
        vm.deal(vm.addr(5), 1 ether);

        uint32 _numWords = 88;
        uint32 _callbackGasLimit = 100000;

        string
            memory VRF_routing_info = "secret1cknezaxnzfys2w8lyyrr7fed9wxejvgq7alhqx";
        string
            memory VRF_routing_code_hash = "0b9395a7550b49d2b8ed73497fd2ebaf896c48950c4186e491ded6d22e58b8c3";

        bytes memory VRF_info = abi.encodePacked(
            '}","routing_info":"',
            VRF_routing_info,
            '","routing_code_hash":"',
            VRF_routing_code_hash,
            '","user_address":"0x0000","user_key":"AAA=","callback_address":"'
        );

        //construct the payload that is sent into the Secret Gateway
        bytes memory payload = bytes.concat(
            '{"data":"{\\"numWords\\":',
            bytes(Strings.toString(_numWords)),
            VRF_info,
            bytes(Base64.encode(bytes.concat(bytes20(vm.addr(5))))), //callback_address
            '","callback_selector":"OLpGFA==","callback_gas_limit":', // 0x38ba4614 hex value already converted into base64, callback_selector of the fulfillRandomWords function
            bytes(Strings.toString(_callbackGasLimit)),
            "}"
        );

        //generate the payload hash using the ethereum hash format for messages
        bytes32 payloadHash = getEthSignedMessageHash(keccak256(payload));

        uint256 requestId = gateway.requestRandomness{value: 0.5 ether}(
            _numWords,
            _callbackGasLimit
        );
        assertEq(requestId, 1, "requestId failed");

        (bytes31 tempPayloadHash, ) = gateway.tasks(1);
        assertEq(tempPayloadHash, bytes31(payloadHash), "payloadHash failed");

        (, bool tempCompleted) = gateway.tasks(1);
        assertEq(tempCompleted, false, "tempCompleted failed");
    }

    /*//////////////////////////////////////////////////////////////
                         Additional Test Cases
    //////////////////////////////////////////////////////////////*/

    function test_OwnerFunctions() public {
        // Test that the owner can call increaseTaskId and payoutBalance
        vm.prank(gatewayOwner);
        gateway.increaseTaskId(100);
        assertEq(gateway.taskId(), 100, "TaskId not updated correctly");

        // Try to call increaseTaskId from notOwner
        vm.prank(notOwner);
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector,
                notOwner
            )
        );
        gateway.increaseTaskId(200);

        // Fund the contract and test payoutBalance
        vm.deal(address(gateway), 1 ether);

        // Owner can call payoutBalance
        uint256 ownerBalanceBefore = gatewayOwner.balance;
        vm.prank(gatewayOwner);
        gateway.payoutBalance();
        uint256 ownerBalanceAfter = gatewayOwner.balance;
        assertEq(
            ownerBalanceAfter - ownerBalanceBefore,
            1 ether,
            "Payout balance failed"
        );

        // Non-owner cannot call payoutBalance
        vm.prank(notOwner);
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector,
                notOwner
            )
        );
        gateway.payoutBalance();
    }

    function test_Send_GasRefund() public {
        // Arrange
        string memory routingInfo = "secret";
        bytes memory payload = "Test Payload";
        bytes32 payloadHash = getEthSignedMessageHash(keccak256(payload));

        Gateway.ExecutionInfo memory assembledInfo = Gateway.ExecutionInfo({
            user_key: "",
            user_pubkey: "",
            routing_code_hash: "",
            task_destination_network: "",
            handle: "",
            nonce: "",
            callback_gas_limit: 100000,
            payload: payload,
            payload_signature: getPayloadSignature(payload, 5)
        });

        uint256 estimatedPrice = gateway.estimateRequestPrice(
            assembledInfo.callback_gas_limit
        );

        // Act
        vm.prank(vm.addr(5), vm.addr(5));
        vm.deal(vm.addr(5), 1 ether);

        // Capture the balance before
        uint256 balanceBefore = vm.addr(5).balance;

        // Call send with more than estimatedPrice
        gateway.send{value: estimatedPrice + 0.1 ether}(
            payloadHash,
            vm.addr(5),
            routingInfo,
            assembledInfo
        );

        // Capture the balance after
        uint256 balanceAfter = vm.addr(5).balance;

        // Assert
        assertEq(
            balanceBefore - balanceAfter,
            estimatedPrice,
            "Excess gas not refunded correctly"
        );
    }

    function test_RequestRandomness_Limits() public {
        vm.prank(vm.addr(5), vm.addr(5));
        vm.deal(vm.addr(5), 1 ether);

        // Test with maximum allowed _numWords
        uint32 _numWords = 2000;
        uint32 _callbackGasLimit = 100000;

        uint256 requestId = gateway.requestRandomness{value: 0.5 ether}(
            _numWords,
            _callbackGasLimit
        );
        assertEq(requestId, 1, "requestId failed");

        // Test exceeding maximum _numWords
        _numWords = 2001;
        vm.expectRevert("Too Many random words Requested");
        gateway.requestRandomness{value: 0.5 ether}(
            _numWords,
            _callbackGasLimit
        );
    }

    function test_PostExecution_Reexecution() public {
        test_PostExecution();

        string memory sourceNetwork = "secret";
        uint256 taskId = 1;

        // Attempt to postExecution again for the same task
        bytes
            memory result = hex"736f6d6520726573756c74000000000000000000000000000000000000000000";
        bytes32 payloadHash = getEthSignedMessageHash(
            keccak256(
                hex"61646420612062756e6368206f66207374756666000000000000000000000000"
            )
        );
        bytes32 packetHash = getPacketHash(
            bytes(sourceNetwork),
            taskId,
            payloadHash,
            result,
            address(gateway),
            hex"373d450c"
        );
        bytes memory packetSignature = getPacketSignature(packetHash, 6);

        Gateway.PostExecutionInfo memory assembledInfo = Gateway
            .PostExecutionInfo({
                payload_hash: payloadHash,
                result: result,
                packet_hash: packetHash,
                packet_signature: packetSignature,
                callback_address: bytes20(address(gateway)),
                callback_selector: hex"373d450c",
                callback_gas_limit: bytes4(uint32(300000))
            });

        vm.expectRevert("Task Already Completed");
        gateway.postExecution(taskId, sourceNetwork, assembledInfo);
    }

    function test_TasksFromMultipleUsers() public {
        // Arrange
        string memory routingInfo = "secret";

        // User 1
        bytes memory payload1 = "User1 Payload";
        bytes32 payloadHash1 = getEthSignedMessageHash(keccak256(payload1));
        Gateway.ExecutionInfo memory assembledInfo1 = Gateway.ExecutionInfo({
            user_key: "",
            user_pubkey: "",
            routing_code_hash: "",
            task_destination_network: "",
            handle: "",
            nonce: "",
            callback_gas_limit: 100000,
            payload: payload1,
            payload_signature: getPayloadSignature(payload1, 5)
        });

        // User 2
        bytes memory payload2 = "User2 Payload";
        bytes32 payloadHash2 = getEthSignedMessageHash(keccak256(payload2));
        Gateway.ExecutionInfo memory assembledInfo2 = Gateway.ExecutionInfo({
            user_key: "",
            user_pubkey: "",
            routing_code_hash: "",
            task_destination_network: "",
            handle: "",
            nonce: "",
            callback_gas_limit: 100000,
            payload: payload2,
            payload_signature: getPayloadSignature(payload2, 6)
        });

        // Act
        vm.prank(vm.addr(5), vm.addr(5));
        vm.deal(vm.addr(5), 1 ether);
        gateway.send{value: 0.5 ether}(
            payloadHash1,
            vm.addr(5),
            routingInfo,
            assembledInfo1
        );
        vm.prank(vm.addr(6), vm.addr(6));
        vm.deal(vm.addr(6), 1 ether);
        gateway.send{value: 0.5 ether}(
            payloadHash2,
            vm.addr(6),
            routingInfo,
            assembledInfo2
        );

        // Assert
        (bytes31 tempPayloadHash1, ) = gateway.tasks(1);
        assertEq(
            tempPayloadHash1,
            bytes31(payloadHash1),
            "Task 1 payloadHash failed"
        );

        (bytes31 tempPayloadHash2, ) = gateway.tasks(2);
        assertEq(
            tempPayloadHash2,
            bytes31(payloadHash2),
            "Task 2 payloadHash failed"
        );
    }

    function test_TaskCompletionOrder() public {
        // Arrange and create multiple tasks
        test_TasksFromMultipleUsers();

        // Complete Task 2 before Task 1
        string memory sourceNetwork = "secret";
        uint256 taskId = 2;

        // Complete Task 2
        bytes memory result2 = "Result for Task 2";
        bytes32 payloadHash2 = getEthSignedMessageHash(
            keccak256("User2 Payload")
        );
        bytes32 packetHash2 = getPacketHash(
            bytes(sourceNetwork),
            taskId,
            payloadHash2,
            result2,
            address(gateway),
            hex"373d450c"
        );
        bytes memory packetSignature2 = getPacketSignature(packetHash2, 6);

        Gateway.PostExecutionInfo memory assembledInfo2 = Gateway
            .PostExecutionInfo({
                payload_hash: payloadHash2,
                result: result2,
                packet_hash: packetHash2,
                packet_signature: packetSignature2,
                callback_address: bytes20(address(gateway)),
                callback_selector: hex"373d450c",
                callback_gas_limit: bytes4(uint32(300000))
            });

        gateway.postExecution(taskId, sourceNetwork, assembledInfo2);

        // Assert Task 2 is completed
        (, bool tempCompleted2) = gateway.tasks(2);
        assertEq(tempCompleted2, true, "Task 2 not completed");

        // Now complete Task 1
        taskId = 1;
        bytes memory result1 = "Result for Task 1";
        bytes32 payloadHash1 = getEthSignedMessageHash(
            keccak256("User1 Payload")
        );
        bytes32 packetHash1 = getPacketHash(
            bytes(sourceNetwork),
            taskId,
            payloadHash1,
            result1,
            address(gateway),
            hex"373d450c"
        );
        bytes memory packetSignature1 = getPacketSignature(packetHash1, 6);

        Gateway.PostExecutionInfo memory assembledInfo1 = Gateway
            .PostExecutionInfo({
                payload_hash: payloadHash1,
                result: result1,
                packet_hash: packetHash1,
                packet_signature: packetSignature1,
                callback_address: bytes20(address(gateway)),
                callback_selector: hex"373d450c",
                callback_gas_limit: bytes4(uint32(300000))
            });

        gateway.postExecution(taskId, sourceNetwork, assembledInfo1);

        // Assert Task 1 is completed
        (, bool tempCompleted1) = gateway.tasks(1);
        assertEq(tempCompleted1, true, "Task 1 not completed");
    }

    function test_RequestRandomness_PaidCallbackFeeTooLow() public {
        vm.prank(vm.addr(5), vm.addr(5));
        vm.deal(vm.addr(5), 1 ether);

        vm.txGasPrice(100 gwei);

        uint32 _numWords = 10;
        uint32 _callbackGasLimit = 100000;

        // Estimate the required fee
        uint256 estimatedPrice = gateway.estimateRequestPrice(
            _callbackGasLimit
        );

        // Provide less than the estimatedPrice
        vm.expectRevert("Paid Callback Fee Too Low");
        gateway.requestRandomness{value: estimatedPrice - 1}(
            _numWords,
            _callbackGasLimit
        );
    }

    function test_Send_InvalidPayloadHash() public {
        string memory routingInfo = "secret";
        bytes memory payload = "Test Payload";
        bytes32 invalidPayloadHash = keccak256("Invalid Payload");

        Gateway.ExecutionInfo memory assembledInfo = Gateway.ExecutionInfo({
            user_key: "",
            user_pubkey: "",
            routing_code_hash: "",
            task_destination_network: "",
            handle: "",
            nonce: "",
            callback_gas_limit: 100000,
            payload: payload,
            payload_signature: getPayloadSignature(payload, 5)
        });

        vm.prank(vm.addr(5), vm.addr(5));
        vm.deal(vm.addr(5), 1 ether);
        vm.expectRevert("Invalid Payload Hash");
        gateway.send{value: 0.5 ether}(
            invalidPayloadHash,
            vm.addr(5),
            routingInfo,
            assembledInfo
        );
    }

    function test_EstimateRequestPrice() public {
        uint32 callbackGasLimit = 100000;
        uint256 estimatedPrice = gateway.estimateRequestPrice(callbackGasLimit);

        // Assuming tx.gasprice is accessible, but in tests it might be zero
        // So we'll just check that estimatedPrice is correct
        uint256 expectedPrice = callbackGasLimit * tx.gasprice;
        assertEq(estimatedPrice, expectedPrice, "Estimated price incorrect");
    }

    function test_RecoverSigner() public {
        bytes32 messageHash = keccak256("Test Message");
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(5, ethSignedMessageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        address recoveredSigner = gateway.recoverSigner(
            ethSignedMessageHash,
            signature
        );
        assertEq(recoveredSigner, vm.addr(5), "Recovered signer incorrect");

        // Test with invalid signature
        bytes32 wrongEthSignedMessageHash = getEthSignedMessageHash(
            keccak256("Wrong Message")
        );
        recoveredSigner = gateway.recoverSigner(
            wrongEthSignedMessageHash,
            signature
        );
        assertTrue(
            recoveredSigner != vm.addr(5),
            "Recovered signer should be incorrect"
        );
    }

    function test_PostExecution_InvalidPacketHash() public {
        test_PreExecution();

        string memory sourceNetwork = "secret";
        uint256 taskId = 1;

        // bytes32 string encoding of "add a bunch of stuff"
        bytes
            memory payload = hex"61646420612062756e6368206f66207374756666000000000000000000000000";
        bytes32 payloadHash = getEthSignedMessageHash(keccak256(payload));

        // bytes32 string encoding of "some result"
        bytes
            memory result = hex"736f6d6520726573756c74000000000000000000000000000000000000000000";
        bytes32 invalidPacketHash = keccak256("Invalid Packet Hash");
        bytes memory packetSignature = getPacketSignature(invalidPacketHash, 6);

        Gateway.PostExecutionInfo memory assembledInfo = Gateway
            .PostExecutionInfo({
                payload_hash: payloadHash,
                result: result,
                packet_hash: invalidPacketHash,
                packet_signature: packetSignature,
                callback_address: bytes20(address(gateway)),
                callback_selector: hex"373d450c",
                callback_gas_limit: bytes4(uint32(300000))
            });

        vm.expectRevert("Invalid Packet Hash");
        gateway.postExecution(taskId, sourceNetwork, assembledInfo);
    }
}
