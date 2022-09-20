// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "forge-std/console2.sol";
import {Gateway} from "../src/Gateway.sol";
import {Client} from "../src/Client.sol";
import {Util} from "../src/Util.sol";

contract ContractTest is Test {
    /*//////////////////////////////////////////////////////////////
                                SETUP
    //////////////////////////////////////////////////////////////*/

    Gateway internal gateway;
    Client internal client;
    address deployer;
    address notOwner;

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
        string handle,
        bytes12 nonce
    );

    event logCompletedTask(uint256 indexed task_id, bytes32 payload_hash, bytes32 result_hash);

    event ComputedResult(uint256 indexed taskId, bytes result);

    function setUp() public {
        deployer = vm.addr(3);
        notOwner = vm.addr(4);
        vm.prank(deployer);
        gateway = new Gateway();
        client = new Client(address(gateway));
    }

    /*//////////////////////////////////////////////////////////////
                           Helper Functions
    //////////////////////////////////////////////////////////////*/

    function getPayloadHash(bytes memory _payload) public pure returns (bytes32) {
        return keccak256(abi.encode(_payload));
    }

    function getResultHash(bytes memory _result) public pure returns (bytes32) {
        return keccak256(abi.encode(_result));
    }

    function getRouteInfoHash(string memory _routingInfo) public pure returns (bytes32) {
        return keccak256(abi.encode(_routingInfo));
    }

    function getRoutingInfoSignature(string memory _routingInfo, uint256 _foundryPkey) public returns (bytes memory) {
        bytes32 routeHash = getRouteInfoHash(_routingInfo);
        bytes32 routeEthSignedMessageHash = Util.getEthSignedMessageHash(routeHash);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(_foundryPkey, routeEthSignedMessageHash);
        bytes memory routingInfoSig = abi.encodePacked(r1, s1, v1);

        return routingInfoSig;
    }

    function getPayloadSignature(bytes memory _payload, uint256 _foundryPkey) public returns (bytes memory) {
        bytes32 payloadHash = getPayloadHash(_payload);
        bytes32 payloadEthSignedMessageHash = Util.getEthSignedMessageHash(payloadHash);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(_foundryPkey, payloadEthSignedMessageHash);
        bytes memory payloadSig = abi.encodePacked(r2, s2, v2);

        return payloadSig;
    }

    function getPacketSignature(bytes32 _packetHash, uint256 _foundryPkey) public returns (bytes memory) {
        bytes32 packetEthSignedMessageHash = Util.getEthSignedMessageHash(_packetHash);
        (uint8 v3, bytes32 r3, bytes32 s3) = vm.sign(_foundryPkey, packetEthSignedMessageHash);
        bytes memory packetSig = abi.encodePacked(r3, s3, v3);

        return packetSig;
    }

    function getResultSignature(bytes memory _result, uint256 _foundryPkey) public returns (bytes memory) {
        bytes32 resultHash = getResultHash(_result);
        bytes32 resultEthSignedMessageHash = Util.getEthSignedMessageHash(resultHash);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(_foundryPkey, resultEthSignedMessageHash);
        bytes memory resultSig = abi.encodePacked(r2, s2, v2);

        return resultSig;
    }

    /*//////////////////////////////////////////////////////////////
                           Test Cases
    //////////////////////////////////////////////////////////////*/

    function test_CheckTheOwnerOfTheContract() public {
        address owner = gateway.owner();
        assertEq(deployer, owner);
    }

    function test_OwnerCanInitialize() public {
        vm.prank(deployer);
        address tempAddress = vm.addr(5);

        gateway.initialize(tempAddress);

        assertEq(tempAddress, gateway.masterVerificationAddress());
    }

    function testFail_NonOwnerCannotInitialize() public {
        vm.startPrank(notOwner);
        address tempAddress = vm.addr(5);
        gateway.initialize(tempAddress);
        vm.stopPrank();
    }

    function test_OwnerCanUpdateRouteWithValidSignature() public {
        // Set the Master Verrification Key below
        vm.prank(deployer);
        address masterVerificationKey = vm.addr(2);

        gateway.initialize(masterVerificationKey);

        address SampleVerificationAddress = vm.addr(6);
        string memory sampleRoute = "secret";

        // Update the route with with masterVerificationKey signature
        bytes32 routeHash = Util.getRouteHash(sampleRoute, SampleVerificationAddress);
        bytes32 ethSignedMessageHash = Util.getEthSignedMessageHash(routeHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(2, ethSignedMessageHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(deployer);
        gateway.updateRoute(sampleRoute, SampleVerificationAddress, sig);

        assertEq(gateway.route("secret"), SampleVerificationAddress);
    }

    function testFail_OwnerCannotUpdateRouteWithoutValidSignature() public {
        // Set the Master Verrification Key below
        vm.prank(deployer);
        address masterVerificationKey = vm.addr(5);

        gateway.initialize(masterVerificationKey);

        address SampleVerificationAddress = vm.addr(6);
        string memory sampleRoute = "secret";

        // Update the route with wrong masterVerificationKey signature
        bytes32 routeHash = Util.getRouteHash(sampleRoute, SampleVerificationAddress);
        bytes32 ethSignedMessageHash = Util.getEthSignedMessageHash(routeHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(7, ethSignedMessageHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(deployer);
        gateway.updateRoute(sampleRoute, SampleVerificationAddress, sig);

        vm.expectRevert(abi.encodeWithSignature("InvalidSignature()"));
    }

    function testFail_NonOwnerCannotUpdateRouteWithValidSignature() public {
        // Set the Master Verrification Key below
        vm.prank(deployer);
        address masterVerificationKey = vm.addr(5);

        gateway.initialize(masterVerificationKey);

        address SampleVerificationAddress = vm.addr(6);
        string memory sampleRoute = "secret";

        // Update the route with  masterVerificationKey signature
        bytes32 routeHash = Util.getRouteHash(sampleRoute, SampleVerificationAddress);
        bytes32 ethSignedMessageHash = Util.getEthSignedMessageHash(routeHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(5, ethSignedMessageHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        gateway.updateRoute(sampleRoute, SampleVerificationAddress, sig);
    }

    function testFail_NonOwnerCannotUpdateRouteWithoutValidSignature() public {
        // Set the Master Verrification Key below
        vm.prank(deployer);
        address masterVerificationKey = vm.addr(5);

        gateway.initialize(masterVerificationKey);

        address SampleVerificationAddress = vm.addr(6);
        string memory sampleRoute = "secret";

        // Update the route with  wrong masterVerificationKey signature
        bytes32 routeHash = Util.getRouteHash(sampleRoute, SampleVerificationAddress);
        bytes32 ethSignedMessageHash = Util.getEthSignedMessageHash(routeHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(7, ethSignedMessageHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        gateway.updateRoute(sampleRoute, SampleVerificationAddress, sig);
    }

    function test_PreExecution() public {
        // USER ADDRESS       ----->   vm.addr(5);
        // CALLBACK ADDRESS   ----->   vm.addr(7);

        bytes4 callbackSelector = bytes4(abi.encodeWithSignature("callback(uint256 _taskId,bytes memory _result)"));
        string memory sourceNetwork = "ethereum";

        string memory routingInfo = "secret";

        // bytes32 string encoding of "add a bunch of stuff"
        bytes memory payload = "0x61646420612062756e6368206f66207374756666000000000000000000000000";
        bytes32 payloadHash = getPayloadHash(payload);
        payloadHash = Util.getEthSignedMessageHash(payloadHash);

        // encoding bytes of "some public key"
        bytes memory userPublicKey = "0x736f6d65207075626c6963206b65790000000000000000000000000000000000";

        Util.Task memory assembledTask = Util.Task({
            callback_address: vm.addr(7),
            callback_selector: callbackSelector,
            user_address: vm.addr(5),
            source_network: sourceNetwork,
            routing_info: routingInfo,
            payload_hash: payloadHash,
            completed: false
        });

        Util.ExecutionInfo memory assembledInfo = Util.ExecutionInfo({
            user_key: userPublicKey,
            routing_code_hash: "some RoutingCodeHash",
            handle: "some kinda handle",
            nonce: "ssssssssssss",
            payload: payload,
            payload_signature: getPayloadSignature(payload, 5)
        });

        vm.expectEmit(true, true, true, true);
        emit logNewTask(
            1,
            sourceNetwork,
            vm.addr(5),
            routingInfo,
            "some RoutingCodeHash",
            payload,
            payloadHash,
            getPayloadSignature(payload, 5),
            userPublicKey,
            "some kinda handle",
            "ssssssssssss"
            );
        gateway.preExecution(assembledTask, assembledInfo);

        (address tempCallbackAddress,,,,,,) = gateway.tasks(1);
        assertEq(tempCallbackAddress, vm.addr(7));

        (, bytes4 tempCallbackSelector,,,,,) = gateway.tasks(1);
        assertEq(tempCallbackSelector, callbackSelector);

        (,, address tempUserAddress,,,,) = gateway.tasks(1);
        assertEq(tempUserAddress, vm.addr(5));

        (,,, string memory tempSourceNetwork,,,) = gateway.tasks(1);
        assertEq(tempSourceNetwork, sourceNetwork);

        (,,,, string memory tempRoutingInfo,,) = gateway.tasks(1);
        assertEq(tempRoutingInfo, routingInfo);

        (,,,,, bytes32 tempPayloadHash,) = gateway.tasks(1);
        assertEq(tempPayloadHash, payloadHash);

        (,,,,,, bool tempCompleted) = gateway.tasks(1);
        assertEq(tempCompleted, false);
    }

    function testFail_CannotPreExecutionWithoutValidPayloadSig() public {
        // USER ADDRESS       ----->   vm.addr(5);
        // CALLBACK ADDRESS   ----->   vm.addr(6);

        bytes4 callbackSelector = bytes4(abi.encodeWithSignature("callback(uint256 _taskId,bytes memory _result)"));
        string memory sourceNetwork = "ethereum";

        string memory routingInfo = "secret";

        // bytes32 string encoding of "add a bunch of stuff"
        bytes memory payload = "0x61646420612062756e6368206f66207374756666000000000000000000000000";
        bytes32 payloadHash = getPayloadHash(payload);
        payloadHash = Util.getEthSignedMessageHash(payloadHash);

        // encoding bytes of "some public key"
        bytes memory userPublicKey = "0x736f6d65207075626c6963206b65790000000000000000000000000000000000";

        Util.Task memory assembledTask = Util.Task({
            callback_address: vm.addr(6),
            callback_selector: callbackSelector,
            user_address: vm.addr(5),
            source_network: sourceNetwork,
            routing_info: routingInfo,
            payload_hash: payloadHash,
            completed: false
        });

        Util.ExecutionInfo memory assembledInfo = Util.ExecutionInfo({
            user_key: userPublicKey,
            routing_code_hash: "some RoutingCodeHash",
            handle: "some kinda handle",
            nonce: "ssssssssssss",
            payload: payload,
            payload_signature: getPayloadSignature(payload, 7)
        });

        vm.expectEmit(true, true, true, true);
        emit logNewTask(
            1,
            sourceNetwork,
            vm.addr(5),
            routingInfo,
            "some RoutingCodeHash",
            payload,
            payloadHash,
            getPayloadSignature(payload, 5),
            userPublicKey,
            "some kinda handle",
            "ssssssssssss"
            );
        gateway.preExecution(assembledTask, assembledInfo);

        vm.expectRevert(abi.encodeWithSignature("InvalidSignature()"));
    }

    function test_PostExecution() public {
        test_OwnerCanUpdateRouteWithValidSignature();
        test_PreExecution();

        string memory sourceNetwork = "secret";
        uint256 taskId = 1;

        // bytes32 string encoding of "add a bunch of stuff"
        bytes memory payload = "0x61646420612062756e6368206f66207374756666000000000000000000000000";
        bytes32 payloadHash = getPayloadHash(payload);
        payloadHash = Util.getEthSignedMessageHash(payloadHash);

        // bytes32 string encoding of "some result"
        bytes memory result = "0x736f6d6520726573756c74000000000000000000000000000000000000000000";
        bytes32 resultHash = getResultHash(result);
        resultHash = Util.getEthSignedMessageHash(resultHash);

        Util.PostExecutionInfo memory assembledInfo = Util.PostExecutionInfo({
            payload_hash: payloadHash,
            payload_signature: getPayloadSignature(payload, 6),
            result: result,
            result_hash: resultHash,
            result_signature: getResultSignature(result, 6),
            packet_hash: resultHash,
            packet_signature: getResultSignature(result, 6)
        });

        vm.expectEmit(true, true, true, true);
        emit logCompletedTask(taskId, payloadHash, resultHash);

        gateway.postExecution(taskId, sourceNetwork, assembledInfo);

        (,,,,,, bool tempCompleted) = gateway.tasks(1);
        assertEq(tempCompleted, true);
    }

    function testFail_PostExecutionWithoutMapStoredAddressSignatures() public {
        test_OwnerCanUpdateRouteWithValidSignature();
        test_PreExecution();

        string memory sourceNetwork = "secret";
        uint256 taskId = 1;

        // bytes32 string encoding of "add a bunch of stuff"
        bytes memory payload = "0x61646420612062756e6368206f66207374756666000000000000000000000000";
        bytes32 payloadHash = getPayloadHash(payload);
        payloadHash = Util.getEthSignedMessageHash(payloadHash);

        // bytes32 string encoding of "some result"
        bytes memory result = "0x736f6d6520726573756c74000000000000000000000000000000000000000000";
        bytes32 resultHash = getResultHash(result);
        resultHash = Util.getEthSignedMessageHash(resultHash);

        Util.PostExecutionInfo memory assembledInfo = Util.PostExecutionInfo({
            payload_hash: payloadHash,
            payload_signature: getPayloadSignature(payload, 8),
            result: result,
            result_hash: resultHash,
            result_signature: getResultSignature(result, 6),
            packet_hash: resultHash,
            packet_signature: getResultSignature(result, 6)
        });

        gateway.postExecution(taskId, sourceNetwork, assembledInfo);

        vm.expectRevert(abi.encodeWithSignature("InvalidSignature()"));
    }

    /*//////////////////////////////////////////////////////////////
                      Stubbed Value Case Setup
    //////////////////////////////////////////////////////////////*/

    function test_PreExecutionSetupForExplicitCase() public {
        // CALLBACK ADDRESS   ----->   vm.addr(7);

        bytes4 callbackSelector = bytes4(abi.encodeWithSignature("callback(uint256 _taskId,bytes memory _result)"));
        string memory sourceNetwork = "ethereum";
        address userAddress = 0x49F7552065228e5abF44e144cc750aEA4F711Dc3;

        string memory routingInfo = "secret";

        // bytes32 string encoding of "add a bunch of stuff"
        bytes memory payload = "0x61646420612062756e6368206f66207374756666000000000000000000000000";
        bytes32 payloadHash = hex"ea57f8cfce0dca7528ff349328b9a524dbbd49fe724026da575aed40cd3ac2c4";
        bytes memory payloadSignature =
            hex"293fb5fe48d81aadd26574aca54509804f628a851d7df4e3356b0e191ef5b11c33f07e7eeb0494384df6f3f636e2fc0fcf64ee3fb0d5e3d6f3302a81325bd06f1c";

        // encoding bytes of "some public key"
        bytes memory userPublicKey = "0x736f6d65207075626c6963206b65790000000000000000000000000000000000";

        Util.Task memory assembledTask = Util.Task({
            callback_address: vm.addr(7),
            callback_selector: callbackSelector,
            user_address: userAddress,
            source_network: sourceNetwork,
            routing_info: routingInfo,
            payload_hash: payloadHash,
            completed: false
        });

        Util.ExecutionInfo memory assembledInfo = Util.ExecutionInfo({
            user_key: userPublicKey,
            routing_code_hash: "some RoutingCodeHash",
            handle: "some kinda handle",
            nonce: "ssssssssssss",
            payload: payload,
            payload_signature: payloadSignature
        });

        vm.expectEmit(true, true, true, true);
        emit logNewTask(
            1,
            sourceNetwork,
            userAddress,
            routingInfo,
            "some RoutingCodeHash",
            payload,
            payloadHash,
            payloadSignature,
            userPublicKey,
            "some kinda handle",
            "ssssssssssss"
            );
        gateway.preExecution(assembledTask, assembledInfo);

        (address tempCallbackAddress,,,,,,) = gateway.tasks(1);
        assertEq(tempCallbackAddress, vm.addr(7));

        (, bytes4 tempCallbackSelector,,,,,) = gateway.tasks(1);
        assertEq(tempCallbackSelector, callbackSelector);

        (,, address tempUserAddress,,,,) = gateway.tasks(1);
        assertEq(tempUserAddress, userAddress);

        (,,, string memory tempSourceNetwork,,,) = gateway.tasks(1);
        assertEq(tempSourceNetwork, sourceNetwork);

        (,,,, string memory tempRoutingInfo,,) = gateway.tasks(1);
        assertEq(tempRoutingInfo, routingInfo);

        (,,,,, bytes32 tempPayloadHash,) = gateway.tasks(1);
        assertEq(tempPayloadHash, payloadHash);

        (,,,,,, bool tempCompleted) = gateway.tasks(1);
        assertEq(tempCompleted, false);
    }

    function test_addressKeySetupForPostExecutionExplicitValues() public {
        // Set the Master Verrification Key below
        vm.prank(deployer);
        address masterVerificationKey = vm.addr(2);

        gateway.initialize(masterVerificationKey);

        address SampleVerificationAddress = 0x49F7552065228e5abF44e144cc750aEA4F711Dc3;
        string memory sampleRoute = "secret";

        // Update the route with with masterVerificationKey signature
        bytes32 routeHash = Util.getRouteHash(sampleRoute, SampleVerificationAddress);
        bytes32 ethSignedMessageHash = Util.getEthSignedMessageHash(routeHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(2, ethSignedMessageHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(deployer);
        gateway.updateRoute(sampleRoute, SampleVerificationAddress, sig);

        assertEq(gateway.route("secret"), SampleVerificationAddress);
    }

    function test_PostExecutionExplicitValues() public {
        test_addressKeySetupForPostExecutionExplicitValues();
        test_PreExecutionSetupForExplicitCase();

        string memory sourceNetwork = "secret";
        uint256 taskId = 1;

        // payload
        bytes32 payloadHash = hex"ea57f8cfce0dca7528ff349328b9a524dbbd49fe724026da575aed40cd3ac2c4";
        bytes memory payloadSignature =
            hex"293fb5fe48d81aadd26574aca54509804f628a851d7df4e3356b0e191ef5b11c33f07e7eeb0494384df6f3f636e2fc0fcf64ee3fb0d5e3d6f3302a81325bd06f1b";

        // result
        bytes memory result = hex"7b226d795f76616c7565223a327d";
        bytes32 resultHash = hex"faef40ffa988468a70a21929200a40f1c8ea9f56fcf79a206ef9713032c4e28b";
        bytes memory resultSignature =
            hex"faad4e82fe9a6a05ef2a4387fca5471fe3bc7b53e81a3c08d4a5514ac7c6fddf2a266cf1c638654c156612a1943dbaf278105f138c5be67ab1eca4253c57ca7f1b";

        // packet
        bytes32 packetHash = hex"923b23c023d0e5e66ac122d9804414f4f9cab06d7a6ce6c4b8c586a1fa57264c";
        bytes memory packetSignature =
            hex"2db95ebb82b81f8240d952e1c6edf021e098de63d32f1f0d3bbbb7daf0e9edbd3378fc42e31d1041467c76388a35078968f1f6f2eb781b5b83054a1d90ba41ff1b";

        Util.PostExecutionInfo memory assembledInfo = Util.PostExecutionInfo({
            payload_hash: payloadHash,
            payload_signature: payloadSignature,
            result: result,
            result_hash: resultHash,
            result_signature: resultSignature,
            packet_hash: packetHash,
            packet_signature: packetSignature
        });

        vm.expectEmit(true, true, true, true);
        emit logCompletedTask(taskId, payloadHash, resultHash);

        gateway.postExecution(taskId, sourceNetwork, assembledInfo);

        (,,,,,, bool tempCompleted) = gateway.tasks(1);
        assertEq(tempCompleted, true);
    }

    /*//////////////////////////////////////////////////////////////
                            Client Test
    //////////////////////////////////////////////////////////////*/

    function test_ClientSendToPreExecution() public {
        string memory sourceNetwork = "ethereum";
        address userAddress = 0x49F7552065228e5abF44e144cc750aEA4F711Dc3;

        string memory routingInfo = "secret";
        bytes memory userPublicKey = "0x736f6d65207075626c6963206b65790000000000000000000000000000000000";

        bytes memory payload = "0x61646420612062756e6368206f66207374756666000000000000000000000000";
        bytes32 payloadHash = hex"ea57f8cfce0dca7528ff349328b9a524dbbd49fe724026da575aed40cd3ac2c4";
        bytes memory payloadSignature =
            hex"293fb5fe48d81aadd26574aca54509804f628a851d7df4e3356b0e191ef5b11c33f07e7eeb0494384df6f3f636e2fc0fcf64ee3fb0d5e3d6f3302a81325bd06f1c";

        Util.ExecutionInfo memory assembledInfo = Util.ExecutionInfo({
            user_key: userPublicKey,
            routing_code_hash: "some RoutingCodeHash",
            handle: "some kinda handle",
            nonce: "ssssssssssss",
            payload: payload,
            payload_signature: payloadSignature
        });

        vm.expectEmit(true, true, true, true);
        emit logNewTask(
            1,
            sourceNetwork,
            userAddress,
            routingInfo,
            "some RoutingCodeHash",
            payload,
            payloadHash,
            payloadSignature,
            userPublicKey,
            "some kinda handle",
            "ssssssssssss"
            );

        client.send(userAddress, sourceNetwork, routingInfo, payloadHash, assembledInfo);

        (address tempCallbackAddress,,,,,,) = gateway.tasks(1);
        assertEq(tempCallbackAddress, address(client));

        (, bytes4 tempCallbackSelector,,,,,) = gateway.tasks(1);
        assertEq(tempCallbackSelector, client.callback.selector);

        (,, address tempUserAddress,,,,) = gateway.tasks(1);
        assertEq(tempUserAddress, userAddress);

        (,,, string memory tempSourceNetwork,,,) = gateway.tasks(1);
        assertEq(tempSourceNetwork, sourceNetwork);

        (,,,, string memory tempRoutingInfo,,) = gateway.tasks(1);
        assertEq(tempRoutingInfo, routingInfo);

        (,,,,, bytes32 tempPayloadHash,) = gateway.tasks(1);
        assertEq(tempPayloadHash, payloadHash);

        (,,,,,, bool tempCompleted) = gateway.tasks(1);
        assertEq(tempCompleted, false);
    }

    function test_PostExecutionToClientCallback() public {
        test_ClientSendToPreExecution();

        string memory sourceNetwork = "secret";
        uint256 taskId = 1;

        // payload
        bytes32 payloadHash = hex"ea57f8cfce0dca7528ff349328b9a524dbbd49fe724026da575aed40cd3ac2c4";
        bytes memory payloadSignature =
            hex"293fb5fe48d81aadd26574aca54509804f628a851d7df4e3356b0e191ef5b11c33f07e7eeb0494384df6f3f636e2fc0fcf64ee3fb0d5e3d6f3302a81325bd06f1b";

        // result
        bytes memory result = hex"7b226d795f76616c7565223a327d";
        bytes32 resultHash = hex"faef40ffa988468a70a21929200a40f1c8ea9f56fcf79a206ef9713032c4e28b";
        bytes memory resultSignature =
            hex"faad4e82fe9a6a05ef2a4387fca5471fe3bc7b53e81a3c08d4a5514ac7c6fddf2a266cf1c638654c156612a1943dbaf278105f138c5be67ab1eca4253c57ca7f1b";

        // packet
        bytes32 packetHash = hex"923b23c023d0e5e66ac122d9804414f4f9cab06d7a6ce6c4b8c586a1fa57264c";
        bytes memory packetSignature =
            hex"2db95ebb82b81f8240d952e1c6edf021e098de63d32f1f0d3bbbb7daf0e9edbd3378fc42e31d1041467c76388a35078968f1f6f2eb781b5b83054a1d90ba41ff1b";

        Util.PostExecutionInfo memory assembledInfo = Util.PostExecutionInfo({
            payload_hash: payloadHash,
            payload_signature: payloadSignature,
            result: result,
            result_hash: resultHash,
            result_signature: resultSignature,
            packet_hash: packetHash,
            packet_signature: packetSignature
        });

        vm.expectEmit(true, true, true, true);
        emit ComputedResult(taskId, result);

        gateway.postExecution(taskId, sourceNetwork, assembledInfo);

        (,,,,,, bool tempCompleted) = gateway.tasks(1);
        assertEq(tempCompleted, true);
    }
}
