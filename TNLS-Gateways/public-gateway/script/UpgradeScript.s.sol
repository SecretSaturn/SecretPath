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
        
        gatewayProxyAdmin = ProxyAdmin(0x7C0f8810f989cB92533b09c3535B1EfA80393EAD);

        bytes memory selector = abi.encodeWithSelector(Gateway.upgradeHandler.selector);
        gatewayProxyAdmin.upgradeAndCall(ITransparentUpgradeableProxy(0xBFE44aF8e40B6468946e9AA88fe2c6c9D0352F62), address(newGatewayLogic),selector);

        vm.stopBroadcast();
    }
}