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

    function run() public {
        vm.startBroadcast();

        // Deploy New Gateway Logic Contract
        //newGatewayLogic = new Gateway();
        newGatewayLogic = Gateway(0x05Ab2c25F67B6ACA9170144FcC61dc01e2b6b34C);
        
        gatewayProxyAdmin = ProxyAdmin(0xdDC6d94d9f9FBb0524f069882d7C98241040472E);

        bytes memory selector = abi.encodeWithSelector(Gateway.upgradeHandler.selector);
        gatewayProxyAdmin.upgradeAndCall(ITransparentUpgradeableProxy(0xfaFCfceC4e29e9b4ECc8C0a3f7df1011580EEEf2), address(newGatewayLogic),selector);

        vm.stopBroadcast();
    }
}