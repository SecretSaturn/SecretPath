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
        
        transparentProxy = ITransparentUpgradeableProxy(0x874303B788c8A13a39EFA38ab6C3b77cd4578129);
        gatewayProxyAdmin = ProxyAdmin(0xd3C10BA03470fbD905046705824DeB047B8aAB54);

        bytes memory selector = abi.encodeWithSelector(Gateway.upgradeHandler.selector);
        gatewayProxyAdmin.upgradeAndCall(transparentProxy, address(newGatewayLogic),selector);

        vm.stopBroadcast();
    }
}