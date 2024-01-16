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


contract DeployScript is Script {
    function setUp() public {}

    address deployer;
    ProxyAdmin proxyAdmin;
    Gateway gatewayLogic;
    TransparentUpgradeableProxy gatewayProxy;
    RandomnessReciever randomnessAddress;

    uint256 privKey = vm.envUint("ETH_PRIVATE_KEY");


    function run() public {
        deployer = vm.rememberKey(privKey);
        vm.startBroadcast();

        // Deploy Gateway Logic Contract
        gatewayLogic = new Gateway();

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

        // Cast the proxy address to the Gateway interface
        Gateway gateway = Gateway(address(gatewayProxy));
        
        randomnessAddress = new RandomnessReciever();
        console2.logAddress(address(gateway));
        console2.logAddress(deployer);

        randomnessAddress.setGatewayAddress(address(gateway));

        vm.stopBroadcast();
    }
}