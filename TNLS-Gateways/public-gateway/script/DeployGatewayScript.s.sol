// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import "forge-std/Vm.sol";
import "forge-std/Script.sol";
import {Gateway} from "../src/Gateway.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";


contract DeployGatewayScript is Script {
    function setUp() public {}

    ProxyAdmin proxyAdmin;
    Gateway gatewayLogic;
    TransparentUpgradeableProxy gatewayProxy;

    function run() public {
        vm.startBroadcast();

        // Deploy Gateway Logic Contract
        gatewayLogic = new Gateway(address(0x0));

        // Prepare initializer data for Gateway
        bytes memory initializerData = abi.encodeWithSelector(
            Gateway.initialize.selector
        );

        // Deploy TransparentUpgradeableProxy
        gatewayProxy = new TransparentUpgradeableProxy(
            address(gatewayLogic),
            address(msg.sender),
            initializerData
        );

        vm.stopBroadcast();
    }
}