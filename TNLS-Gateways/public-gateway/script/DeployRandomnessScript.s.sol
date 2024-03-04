// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "forge-std/console2.sol";
import "forge-std/Script.sol";
import {Gateway} from "../src/Gateway.sol";
import {RandomnessReciever} from "../src/RandomnessReciever.sol";


contract DeployRandomnessScript is Script {
    function setUp() public {}

    RandomnessReciever randomnessAddress;

    function run() public {
        vm.startBroadcast();

        Gateway gateway = Gateway(0x3879E146140b627a5C858a08e507B171D9E43139);
        randomnessAddress = new RandomnessReciever();
        console2.logAddress(address(randomnessAddress));

        randomnessAddress.setGatewayAddress(address(gateway));

        vm.stopBroadcast();
    }
}