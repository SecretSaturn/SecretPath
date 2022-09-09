// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Script.sol";
import "../src/Contract.sol";

contract ContractScript is Script {
    function setUp() public {}

    Gateway gateway;

    function run() public {
        vm.startBroadcast();

        gateway = new Gateway();

        vm.stopBroadcast();
    }
}