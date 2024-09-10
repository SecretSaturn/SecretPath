// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import "forge-std/Vm.sol";
import "forge-std/Script.sol";
import {Gateway} from "../src/Gateway.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";


contract UpgradeScript is Script {
    function setUp() public {}

    Gateway newGatewayLogic;
    ProxyAdmin gatewayProxyAdmin;
    ITransparentUpgradeableProxy transparentProxy;

    function run() public {
        vm.startBroadcast();

        // Deploy New Gateway Logic Contract
        newGatewayLogic = new Gateway(address(0x0));
        //newGatewayLogic = Gateway(0x59D8C9591dB7179c5d592c5bCD42694021885aFC);
        
        transparentProxy = ITransparentUpgradeableProxy(0x3879E146140b627a5C858a08e507B171D9E43139);
        gatewayProxyAdmin = ProxyAdmin(0x38476c18226C98C821eE1DFc368D49691d44cE68);

        bytes memory selector = abi.encodeWithSelector(Gateway.upgradeHandler.selector);
        gatewayProxyAdmin.upgradeAndCall(transparentProxy, address(newGatewayLogic),selector);

        vm.stopBroadcast();
    }
}