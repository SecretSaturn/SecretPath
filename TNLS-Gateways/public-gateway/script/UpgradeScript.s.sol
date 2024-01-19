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

    address deployer;
    Gateway newGatewayLogic;
    ProxyAdmin gatewayProxyAdmin;

    uint256 privKey = vm.envUint("ETH_PRIVATE_KEY");


    function run() public {
        deployer = vm.rememberKey(privKey);
        vm.startBroadcast();

        // Deploy New Gateway Logic Contract
        newGatewayLogic = new Gateway();
        
        gatewayProxyAdmin = ProxyAdmin(0x9eA72D83533D8B753d000D9C233a80CC08FFb072);

        bytes memory selector = abi.encodeWithSelector(Gateway.upgradeHandler.selector);
        gatewayProxyAdmin.upgradeAndCall(ITransparentUpgradeableProxy(0x286B1e6B58a913E457509f0C30Ad4393C78f4F84), address(newGatewayLogic),selector);

        vm.stopBroadcast();
    }
}