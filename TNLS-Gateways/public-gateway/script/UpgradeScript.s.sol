// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "forge-std/console2.sol";
import "forge-std/Script.sol";
import {Gateway} from "../src/Gateway.sol";
import {RandomnessReceiver} from "../src/RandomnessReceiver.sol";
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
        
        gatewayProxyAdmin = ProxyAdmin(0xCbA9277ccf3Ce4e217D983FB141dcDAa0b66bF8f);

        bytes memory selector = abi.encodeWithSelector(Gateway.upgradeHandler.selector);
        gatewayProxyAdmin.upgradeAndCall(ITransparentUpgradeableProxy(0x4c14a6A0CD2DA2848D3C31285B828F6364087735), address(newGatewayLogic),selector);

        vm.stopBroadcast();
    }
}