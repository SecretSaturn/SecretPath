// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "forge-std/console2.sol";
import "../src/Contract.sol";

contract client {}

contract ContractTest is Test {
    client internal userClient;
    Gateway internal gateway;
    address deployer;
    address notOwner;

    event logNewTask(
        address _callbackAddressLog,
        bytes4 _callbackSelectorLog,
        address _userAddressLog,
        string _sourceNetworkLog,
        string _routingInfoLog,
        bytes _routingInfoSignatureLog,
        bytes _payloadLog,
        bytes32 _payloadHashLog,
        bytes _payloadSignatureLog,
        bytes _packetSignatureLog
    );

     struct TestTask {
        address callbackAddress;
        bytes4 callbackSelector;
        address userAddress;
        string sourceNetwork;
        string routingInfo;
        bytes32 payloadHash;
        bool completed;
     }

    function setUp() public {
        userClient = new client();
        deployer = vm.addr(3);
        notOwner = vm.addr(4);
        vm.prank(deployer);
        gateway = new Gateway();
    }

    // function test_CheckTheOwnerOfTheContract() public {
    //     address owner = gateway.owner();
    //     assertEq(deployer, owner);
    // }

    // function test_OwnerCanInitialize() public {
    //     vm.prank(deployer);
    //     address tempAddress = vm.addr(5);

    //     gateway.initialize(tempAddress);

    //     assertEq(tempAddress, gateway.masterVerificationAddress());
    // }

    // function testFail_NonOwnerCannotInitialize() public {
    //     vm.startPrank(notOwner);
    //     address tempAddress = vm.addr(5);
    //     gateway.initialize(tempAddress);
    //     vm.stopPrank();
    // }

    // function test_OwnerCanUpdateRouteWithValidSignature() public {
    //     // Set the Master Verrification Key below
    //     vm.prank(deployer);
    //     address masterVerificationKey = vm.addr(5);

    //     gateway.initialize(masterVerificationKey);

    //     address SampleVerificationAddress = vm.addr(6);
    //     string memory sampleRoute = "secret";

    //     // Update the route with with masterVerificationKey signature
    //     bytes32 routeHash = gateway.getRouteHash(sampleRoute, SampleVerificationAddress);
    //     bytes32 ethSignedMessageHash = gateway.getEthSignedMessageHash(routeHash);

    //     (uint8 v, bytes32 r, bytes32 s) = vm.sign(5, ethSignedMessageHash);
    //     bytes memory sig = abi.encodePacked(r, s, v);

    //     vm.prank(deployer);
    //     gateway.updateRoute(sampleRoute, SampleVerificationAddress, sig);

    //     assertEq(gateway.route("secret"), SampleVerificationAddress);
    // }

    // function testFail_OwnerCannotUpdateRouteWithoutValidSignature() public {
    //     // Set the Master Verrification Key below
    //     vm.prank(deployer);
    //     address masterVerificationKey = vm.addr(5);

    //     gateway.initialize(masterVerificationKey);

    //     address SampleVerificationAddress = vm.addr(6);
    //     string memory sampleRoute = "secret";

    //     // Update the route with wrong masterVerificationKey signature
    //     bytes32 routeHash = gateway.getRouteHash(sampleRoute, SampleVerificationAddress);
    //     bytes32 ethSignedMessageHash = gateway.getEthSignedMessageHash(routeHash);

    //     (uint8 v, bytes32 r, bytes32 s) = vm.sign(7, ethSignedMessageHash);
    //     bytes memory sig = abi.encodePacked(r, s, v);

    //     vm.prank(deployer);
    //     gateway.updateRoute(sampleRoute, SampleVerificationAddress, sig);

    //     vm.expectRevert(abi.encodeWithSignature("InvalidSignature()"));
    // }

    // function testFail_NonOwnerCannotUpdateRouteWithValidSignature() public {
    //     // Set the Master Verrification Key below
    //     vm.prank(deployer);
    //     address masterVerificationKey = vm.addr(5);

    //     gateway.initialize(masterVerificationKey);

    //     address SampleVerificationAddress = vm.addr(6);
    //     string memory sampleRoute = "secret";

    //     // Update the route with  masterVerificationKey signature
    //     bytes32 routeHash = gateway.getRouteHash(sampleRoute, SampleVerificationAddress);
    //     bytes32 ethSignedMessageHash = gateway.getEthSignedMessageHash(routeHash);

    //     (uint8 v, bytes32 r, bytes32 s) = vm.sign(5, ethSignedMessageHash);
    //     bytes memory sig = abi.encodePacked(r, s, v);

    //     gateway.updateRoute(sampleRoute, SampleVerificationAddress, sig);
    // }

    // function testFail_NonOwnerCannotUpdateRouteWithoutValidSignature() public {
    //     // Set the Master Verrification Key below
    //     vm.prank(deployer);
    //     address masterVerificationKey = vm.addr(5);

    //     gateway.initialize(masterVerificationKey);

    //     address SampleVerificationAddress = vm.addr(6);
    //     string memory sampleRoute = "secret";

    //     // Update the route with  wrong masterVerificationKey signature
    //     bytes32 routeHash = gateway.getRouteHash(sampleRoute, SampleVerificationAddress);
    //     bytes32 ethSignedMessageHash = gateway.getEthSignedMessageHash(routeHash);

    //     (uint8 v, bytes32 r, bytes32 s) = vm.sign(7, ethSignedMessageHash);
    //     bytes memory sig = abi.encodePacked(r, s, v);

    //     gateway.updateRoute(sampleRoute, SampleVerificationAddress, sig);
    // }

    function getRoutingInfoSignature(string memory _routingInfo, uint256 _foundryPkey) public returns (bytes memory) {
        bytes32 routeHash = gateway.getRouteInfoHash(_routingInfo);
        bytes32 routeEthSignedMessageHash = gateway.getEthSignedMessageHash(routeHash);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(_foundryPkey, routeEthSignedMessageHash);
        bytes memory routingInfoSig = abi.encodePacked(r1, s1, v1);

        return routingInfoSig;
    }

    function getPayloadSignature(bytes memory _payload, uint256 _foundryPkey) public returns (bytes memory) {
        bytes32 payloadHash = gateway.getPayloadHash(_payload);
        bytes32 payloadEthSignedMessageHash = gateway.getEthSignedMessageHash(payloadHash);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(_foundryPkey, payloadEthSignedMessageHash);
        bytes memory payloadSig = abi.encodePacked(r2, s2, v2);

        return payloadSig;
    }

    function getPacketSig(bytes32 _packetHash, uint256 _foundryPkey) public returns (bytes memory) {
        bytes32 packetEthSignedMessageHash = gateway.getEthSignedMessageHash(_packetHash);
        (uint8 v3, bytes32 r3, bytes32 s3) = vm.sign(_foundryPkey, packetEthSignedMessageHash);
        bytes memory packetSig = abi.encodePacked(r3, s3, v3);

        return packetSig;
    }

    // function test_PreExecution() public {
        
    //     address userAddress = vm.addr(5);
    //     address callbackAddress = vm.addr(6);
    //     bytes4 callbackSelector = bytes4(abi.encodeWithSignature("transfer(address,uint256)"));
    //     string memory sourceNetwork = "ethereum";
        
    //     string memory routingInfo = "secret";
    //     bytes memory routingInfoSig = getRoutingInfoSignature(routingInfo, 5);

    //     // bytes32 string encoding of "add a bunch of stuff"
    //     bytes memory payload = "0x61646420612062756e6368206f66207374756666000000000000000000000000";
    //     bytes memory payloadSig = getPayloadSignature(payload, 5);
    //     bytes32 payloadHash = gateway.getPayloadHash(payload);

    //     bytes32 packetHash = gateway.getPacketHash(
    //         callbackAddress, callbackSelector, userAddress, sourceNetwork, routingInfo, routingInfoSig, payload, payloadHash, payloadSig
    //     );
    //     bytes memory packetSig = getPacketSig(packetHash, 5);

    //     vm.expectEmit(true, true, true, true);
    //     emit logNewTask(
    //         callbackAddress, callbackSelector, userAddress, sourceNetwork, routingInfo, routingInfoSig, payload, payloadHash, payloadSig, packetSig
    //         );
    //     gateway.preExecution(
    //         callbackAddress, callbackSelector, userAddress, sourceNetwork, routingInfo, routingInfoSig, payload, payloadHash, payloadSig, packetSig
    //     );
        

    //     (address tempCallbackAddress, , , , , ,)= gateway.tasks(1);
    //     assertEq(tempCallbackAddress, callbackAddress);

    //     (,bytes4 tempCallbackSelector , , , , ,)= gateway.tasks(1);
    //     assertEq(tempCallbackSelector, callbackSelector);

    //     (, ,address tempUserAddress , , , ,)= gateway.tasks(1);
    //     assertEq(tempUserAddress, userAddress);

    //     (, , ,string memory tempSourceNetwork , , ,)= gateway.tasks(1);
    //     assertEq(tempSourceNetwork, sourceNetwork);

    //     (, , , ,string memory tempRoutingInfo , ,)= gateway.tasks(1);
    //     assertEq(tempRoutingInfo, routingInfo);

    //     (, , , , , bytes32 tempPayloadHash ,)= gateway.tasks(1);
    //     assertEq(tempPayloadHash, payloadHash);

    //     (, , , , , ,bool tempCompleted)= gateway.tasks(1);
    //     assertEq(tempCompleted, false);


    // }

    function testFail_CannotPreExecutionWithoutValidRoutingInfoSig() public {
        
        address userAddress = vm.addr(5);
        address callbackAddress = vm.addr(6);
        bytes4 callbackSelector = bytes4(abi.encodeWithSignature("transfer(address,uint256)"));
        string memory sourceNetwork = "ethereum";
        
        string memory routingInfo = "secret";
        bytes memory routingInfoSig = getRoutingInfoSignature(routingInfo, 7);

        // bytes32 string encoding of "add a bunch of stuff"
        bytes memory payload = "0x61646420612062756e6368206f66207374756666000000000000000000000000";
        bytes memory payloadSig = getPayloadSignature(payload, 5);
        bytes32 payloadHash = gateway.getPayloadHash(payload);

        bytes32 packetHash = gateway.getPacketHash(
            callbackAddress, callbackSelector, userAddress, sourceNetwork, routingInfo, routingInfoSig, payload, payloadHash, payloadSig
        );
        bytes memory packetSig = getPacketSig(packetHash, 5);

        vm.expectEmit(true, true, true, true);
        emit logNewTask(
            callbackAddress, callbackSelector, userAddress, sourceNetwork, routingInfo, routingInfoSig, payload, payloadHash, payloadSig, packetSig
            );
        gateway.preExecution(
            callbackAddress, callbackSelector, userAddress, sourceNetwork, routingInfo, routingInfoSig, payload, payloadHash, payloadSig, packetSig
        );
        
        vm.expectRevert(abi.encodeWithSignature("InvalidSignature()"));

    }

    function testFail_CannotPreExecutionWithoutValidPayloadSig() public {
        
        address userAddress = vm.addr(5);
        address callbackAddress = vm.addr(6);
        bytes4 callbackSelector = bytes4(abi.encodeWithSignature("transfer(address,uint256)"));
        string memory sourceNetwork = "ethereum";
        
        string memory routingInfo = "secret";
        bytes memory routingInfoSig = getRoutingInfoSignature(routingInfo, 5);

        // bytes32 string encoding of "add a bunch of stuff"
        bytes memory payload = "0x61646420612062756e6368206f66207374756666000000000000000000000000";
        bytes memory payloadSig = getPayloadSignature(payload, 7);
        bytes32 payloadHash = gateway.getPayloadHash(payload);

        bytes32 packetHash = gateway.getPacketHash(
            callbackAddress, callbackSelector, userAddress, sourceNetwork, routingInfo, routingInfoSig, payload, payloadHash, payloadSig
        );
        bytes memory packetSig = getPacketSig(packetHash, 5);

        vm.expectEmit(true, true, true, true);
        emit logNewTask(
            callbackAddress, callbackSelector, userAddress, sourceNetwork, routingInfo, routingInfoSig, payload, payloadHash, payloadSig, packetSig
            );
        gateway.preExecution(
            callbackAddress, callbackSelector, userAddress, sourceNetwork, routingInfo, routingInfoSig, payload, payloadHash, payloadSig, packetSig
        );
        
        vm.expectRevert(abi.encodeWithSignature("InvalidSignature()"));

    }

    function testFail_CannotPreExecutionWithoutValidPacketSig() public {
        
        address userAddress = vm.addr(5);
        address callbackAddress = vm.addr(6);
        bytes4 callbackSelector = bytes4(abi.encodeWithSignature("transfer(address,uint256)"));
        string memory sourceNetwork = "ethereum";
        
        string memory routingInfo = "secret";
        bytes memory routingInfoSig = getRoutingInfoSignature(routingInfo, 5);

        // bytes32 string encoding of "add a bunch of stuff"
        bytes memory payload = "0x61646420612062756e6368206f66207374756666000000000000000000000000";
        bytes memory payloadSig = getPayloadSignature(payload, 5);
        bytes32 payloadHash = gateway.getPayloadHash(payload);

        bytes32 packetHash = gateway.getPacketHash(
            callbackAddress, callbackSelector, userAddress, sourceNetwork, routingInfo, routingInfoSig, payload, payloadHash, payloadSig
        );
        bytes memory packetSig = getPacketSig(packetHash, 7);

        vm.expectEmit(true, true, true, true);
        emit logNewTask(
            callbackAddress, callbackSelector, userAddress, sourceNetwork, routingInfo, routingInfoSig, payload, payloadHash, payloadSig, packetSig
            );
        gateway.preExecution(
            callbackAddress, callbackSelector, userAddress, sourceNetwork, routingInfo, routingInfoSig, payload, payloadHash, payloadSig, packetSig
        );
        
        vm.expectRevert(abi.encodeWithSignature("InvalidSignature()"));

    }

    // function test_PostExecution() public {
    //     // string memory _sourceNetwork,
    //     // string memory _routingInfo,
    //     // bytes memory _routingInfoSignature,
    //     // bytes memory _payload,
    //     // bytes32 _payloadHash,
    //     // bytes memory _payloadSignature,
    //     // bytes memory _packetSignature,
    //     // uint256 _taskId

    //     address userAddress = vm.addr(5);
    //     address callbackAddress = vm.addr(6);
    //     bytes4 callbackSelector = bytes4(abi.encodeWithSignature("transfer(address,uint256)"));
    //     string memory sourceNetwork = "secret";
    //     // encoding of "add a bunch of stuff"
    //     bytes memory payload = "0x61646420612062756e6368206f66207374756666000000000000000000000000";

    //     string memory routingInfo = "ethereum";

    //     // Update the route with  wrong masterVerificationKey signature
    //     bytes32 routeHash = gateway.getRouteHash(routingInfo, userAddress);
    //     bytes32 ethSignedMessageHash = gateway.getEthSignedMessageHash(routeHash);

    //     // vm.startPrank(notOwner);
    //     // address tempAddress = vm.addr(5);
    //     // gateway.initialize(tempAddress);
    //     // vm.stopPrank();
    // }
}