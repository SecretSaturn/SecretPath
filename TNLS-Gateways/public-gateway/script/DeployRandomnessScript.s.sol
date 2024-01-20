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

    address deployer;
    RandomnessReciever randomnessAddress;

    uint256 privKey = vm.envUint("ETH_PRIVATE_KEY");


    function run() public {
        deployer = vm.rememberKey(privKey);
        vm.startBroadcast();

        Gateway gateway = Gateway(0x5e1e92eA6A1b7a58D88619C625FEc5D27147bc64);
        randomnessAddress = new RandomnessReciever();
        console2.logAddress(address(randomnessAddress));

        randomnessAddress.setGatewayAddress(address(gateway));

        vm.stopBroadcast();
    }
}