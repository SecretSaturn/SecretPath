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
        
        transparentProxy = ITransparentUpgradeableProxy(0xfaFCfceC4e29e9b4ECc8C0a3f7df1011580EEEf2);
        gatewayProxyAdmin = ProxyAdmin(0xdDC6d94d9f9FBb0524f069882d7C98241040472E);

        bytes memory selector = abi.encodeWithSelector(Gateway.upgradeHandler.selector);
        gatewayProxyAdmin.upgradeAndCall(transparentProxy, address(newGatewayLogic),selector);

        vm.stopBroadcast();
    }
}