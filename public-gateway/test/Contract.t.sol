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

    function setUp() public {
        userClient = new client();
        deployer = vm.addr(3);
        notOwner = vm.addr(4);
        vm.prank(deployer);
        gateway = new Gateway();
    }

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
        address masterVerificationKey = vm.addr(5);

        gateway.initialize(masterVerificationKey);

        address SampleVerificationAddress = vm.addr(6);
        string memory sampleRoute = "secret";

        // Update the route with with masterVerificationKey signature
        bytes32 routeHash = gateway.getRouteHash(sampleRoute, SampleVerificationAddress);
        bytes32 ethSignedMessageHash = gateway.getEthSignedMessageHash(routeHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(5, ethSignedMessageHash);
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
        bytes32 routeHash = gateway.getRouteHash(sampleRoute, SampleVerificationAddress);
        bytes32 ethSignedMessageHash = gateway.getEthSignedMessageHash(routeHash);

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
        bytes32 routeHash = gateway.getRouteHash(sampleRoute, SampleVerificationAddress);
        bytes32 ethSignedMessageHash = gateway.getEthSignedMessageHash(routeHash);

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
        bytes32 routeHash = gateway.getRouteHash(sampleRoute, SampleVerificationAddress);
        bytes32 ethSignedMessageHash = gateway.getEthSignedMessageHash(routeHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(7, ethSignedMessageHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        gateway.updateRoute(sampleRoute, SampleVerificationAddress, sig);
    }

    function test_PreExecution() public {

        
        // string memory _routingInfo,
        // bytes memory _routingInfoSignature,
    
        // bytes32 _payloadHash,
        // bytes memory _payloadSignature,
        // bytes memory _packetSignatur 
        address userAddress = vm.addr(5);
        address callbackAddress = vm.addr(6); 
        bytes4 callbackSelector = bytes4(abi.encodeWithSignature("transfer(address,uint256)"));
        string memory sourceNetwork = "ethereum";
        // encoding of "add a bunch of stuff"
        bytes memory payload = "0x61646420612062756e6368206f66207374756666000000000000000000000000"; 

        string memory sampleRoute = "secret";

        // Update the route with  wrong masterVerificationKey signature
        bytes32 routeHash = gateway.getRouteHash(sampleRoute, userAddress);
        bytes32 ethSignedMessageHash = gateway.getEthSignedMessageHash(routeHash);

        // vm.startPrank(notOwner);
        // address tempAddress = vm.addr(5);
        // gateway.initialize(tempAddress);
        // vm.stopPrank();
    }

    function test_PostExecution() public {
        // string memory _sourceNetwork,
        // string memory _routingInfo,
        // bytes memory _routingInfoSignature,
        // bytes memory _payload,
        // bytes32 _payloadHash,
        // bytes memory _payloadSignature,
        // bytes memory _packetSignature,
        // uint256 _taskId

        address userAddress = vm.addr(5);
        address callbackAddress = vm.addr(6); 
        bytes4 callbackSelector = bytes4(abi.encodeWithSignature("transfer(address,uint256)"));
        string memory sourceNetwork = "secret";
        // encoding of "add a bunch of stuff"
        bytes memory payload = "0x61646420612062756e6368206f66207374756666000000000000000000000000"; 

        string memory routingInfo = "ethereum";

        // Update the route with  wrong masterVerificationKey signature
        bytes32 routeHash = gateway.getRouteHash(routingInfo, userAddress);
        bytes32 ethSignedMessageHash = gateway.getEthSignedMessageHash(routeHash);

        // vm.startPrank(notOwner);
        // address tempAddress = vm.addr(5);
        // gateway.initialize(tempAddress);
        // vm.stopPrank();
    }
}