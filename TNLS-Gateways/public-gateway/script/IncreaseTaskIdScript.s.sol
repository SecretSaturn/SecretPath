// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "forge-std/console2.sol";
import "forge-std/Script.sol";
import {Gateway} from "../src/Gateway.sol";


contract IncreaseTaskIdScript is Script {
    function setUp() public {}

    address deployer;
    Gateway gateway;

    uint256 privKey = vm.envUint("ETH_PRIVATE_KEY");


    function run() public {
        deployer = vm.rememberKey(privKey);
        vm.startBroadcast();

        // Gateway (Proxy) Contract
        gateway = Gateway(0x22A6ddbf431Fb9D657062B8D6eAB27A9Dd499752);

        //Increase the task_id to the appropriate value
        gateway.increaseTaskId(50);

        vm.stopBroadcast();
    }
}