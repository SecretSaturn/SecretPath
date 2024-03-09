// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

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

        Gateway gateway = Gateway(0x4c14a6A0CD2DA2848D3C31285B828F6364087735);
        randomnessAddress = new RandomnessReceiver();
        console2.logAddress(address(randomnessAddress));

        randomnessAddress.setGatewayAddress(address(gateway));

        vm.stopBroadcast();
    }
}