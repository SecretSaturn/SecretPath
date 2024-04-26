// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import "forge-std/Vm.sol";
import "forge-std/Script.sol";
import {Gateway} from "../src/Gateway.sol";
import {RandomnessReceiver} from "../src/RandomnessReceiver.sol";


contract DeployRandomnessScript is Script {
    function setUp() public {}

    RandomnessReceiver randomnessAddress;

    function run() public {
        vm.startBroadcast();

        Gateway gateway = Gateway(0xfaFCfceC4e29e9b4ECc8C0a3f7df1011580EEEf2);
        randomnessAddress = new RandomnessReceiver();
        console2.logAddress(address(randomnessAddress));

        randomnessAddress.setGatewayAddress(address(gateway));

        vm.stopBroadcast();
    }
}