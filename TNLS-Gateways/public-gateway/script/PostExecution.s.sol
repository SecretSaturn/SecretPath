// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "forge-std/console2.sol";
import "forge-std/Script.sol";
import {Gateway} from "../src/Gateway.sol";


contract PostExecution is Script {
    function setUp() public {}

    address deployer;
    Gateway gateway;

    function run() public {
        vm.startBroadcast();

        // Gateway (Proxy) Contract
        gateway = Gateway(0x874303B788c8A13a39EFA38ab6C3b77cd4578129);

        uint256 taskId = 11;
        string memory sourceNetwork = "pulsar-3";
        Gateway.PostExecutionInfo memory postExecutionInfo = 
        Gateway.PostExecutionInfo ({
            payload_hash: 0x08cd800c7bf881f51780bbb954229ab275c2f8ad57f38a8f36f10017fa2184f5,
            packet_hash: 0x49519db23b304988417ba523ed177850b7efbe86186b2a8a3d8adc65832c0489,
            callback_address: hex"b5cf36c9708c4f728bb8b1059c28cc9b606bd102",
            callback_selector: 0x38ba4614,
            callback_gas_limit: 0x000186a0,
            packet_signature: hex"35b9542f54584a433e21d38e3f5d92c2bbc008958f0fc1fc0638b0f1c366427139485585fffbbc113c0e4b082d63028e4d60e46243a779ebebf2db4ba9f3137f1b",
            result: hex"850f3e45bf017011a69d4f3a9e2967e18fbb7110154a5dbe27206037751689a7"
        });
       //postExecution(uint256 _taskId, string calldata _sourceNetwork, PostExecutionInfo calldata _info)
        gateway.postExecution(taskId, sourceNetwork, postExecutionInfo);

        vm.stopBroadcast();
    }
}