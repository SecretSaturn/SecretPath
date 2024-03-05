// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "forge-std/console2.sol";
import "forge-std/Script.sol";
import {Gateway} from "../src/Gateway.sol";
import {RandomnessReceiver} from "../src/RandomnessReceiver.sol";


contract DeployRandomnessScript is Script {
    function setUp() public {}

    RandomnessReceiver randomnessAddress;

    function run() public {
        vm.startBroadcast();

        Gateway gateway = Gateway(0x3879E146140b627a5C858a08e507B171D9E43139);
        randomnessAddress = new RandomnessReceiver();
        console2.logAddress(address(randomnessAddress));

        randomnessAddress.setGatewayAddress(address(gateway));

        vm.stopBroadcast();
    }
}