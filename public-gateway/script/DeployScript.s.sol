// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "forge-std/console2.sol";
import "forge-std/Script.sol";
import {Gateway} from "../src/Gateway.sol";
import {Client} from "../src/Client.sol";
import {Util} from "../src/Util.sol";

contract DeployScript is Script {
    function setUp() public {}

    Gateway gatewayAddress;
    Client clientAddress;

    uint256 privKey = vm.envUint("ETH_PRIVATE_KEY");
    address deployer = vm.rememberKey(privKey);

    function run() public {
        vm.startBroadcast();

        gatewayAddress = new Gateway();
        clientAddress = new Client(address(gatewayAddress));

        console2.logAddress(address(gatewayAddress));
        console2.logAddress(address(clientAddress));
        console2.logAddress(deployer);

        // Initialize master verification Address
        gatewayAddress.initialize(deployer);

        /// ------ Update Routes Param Setup ------- ///

        string memory route = "secret";
        address verificationAddress = vm.envAddress("SECRET_GATEWAY_ETH_ADDRESS");

        // Update the route with with masterVerificationKey signature
        bytes32 routeHash = Util.getRouteHash(route, verificationAddress);
        bytes32 ethSignedMessageHash = Util.getEthSignedMessageHash(routeHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, ethSignedMessageHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        gatewayAddress.updateRoute(route, verificationAddress, sig);

        vm.stopBroadcast();
    }
}
