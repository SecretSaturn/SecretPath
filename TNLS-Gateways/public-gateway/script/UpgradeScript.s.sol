// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "forge-std/console2.sol";
import "forge-std/Script.sol";
import {Gateway} from "../src/Gateway.sol";
import {RandomnessReciever} from "../src/RandomnessReciever.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";


contract UpgradeScript is Script {
    function setUp() public {}

    Gateway newGatewayLogic;
    ProxyAdmin gatewayProxyAdmin;

    function run() public {
        vm.startBroadcast();

        // Deploy New Gateway Logic Contract
        newGatewayLogic = new Gateway();
        
        gatewayProxyAdmin = ProxyAdmin(0xdDC6d94d9f9FBb0524f069882d7C98241040472E);

        bytes memory selector = abi.encodeWithSelector(Gateway.upgradeHandler.selector);
        gatewayProxyAdmin.upgradeAndCall(ITransparentUpgradeableProxy(0xfaFCfceC4e29e9b4ECc8C0a3f7df1011580EEEf2), address(newGatewayLogic),selector);

        vm.stopBroadcast();
    }
}