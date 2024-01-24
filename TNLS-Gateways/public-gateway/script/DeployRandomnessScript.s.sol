// SPDX-License-Identifier: UNLICENSED
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

        Gateway gateway = Gateway(0x810C253D2b94A6348BFB21a3cF5D33af6606C54A);
        randomnessAddress = new RandomnessReciever();
        console2.logAddress(address(randomnessAddress));

        randomnessAddress.setGatewayAddress(address(gateway));

        vm.stopBroadcast();
    }
}