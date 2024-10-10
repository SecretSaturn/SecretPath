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
        //newGatewayLogic = Gateway(0xE3134d95eBEAb90d08a6eF1e9972fc9F8878FbaA);
        
        transparentProxy = ITransparentUpgradeableProxy(0x8EaAB5e8551781F3E8eb745E7fcc7DAeEFd27b1f);
        gatewayProxyAdmin = ProxyAdmin(0xb352D4449dC7355d4478784027d7AfAe69843085);

        bytes memory selector = abi.encodeWithSelector(Gateway.upgradeHandler.selector);
        gatewayProxyAdmin.upgradeAndCall(transparentProxy, address(newGatewayLogic),selector);

        vm.stopBroadcast();
    }
}