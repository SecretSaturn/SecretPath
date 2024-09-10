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

    /* 
    To get the execution data, use for example: 
    secretcli query wasm query secret10ex7r7c4y704xyu086lf74ymhrqhypayfk7fkj '{"get_execution_result": {"task":{"network":"11155111", "task_id":"969"}}}'
    */
    function run() public {
        vm.startBroadcast();

        // Gateway (Proxy) Contract
        gateway = Gateway(0x874303B788c8A13a39EFA38ab6C3b77cd4578129);

        uint256 taskId = 60;
        string memory sourceNetwork = "pulsar-3";
        Gateway.PostExecutionInfo memory postExecutionInfo = Gateway
            .PostExecutionInfo({
                payload_hash: 0x35d0a37ebbbc8c1beb5ae017648843288862edc355894b057837660ccf57c014,
                packet_hash: 0x0c27bf4795f85ecccf6e6db692d6800ecbc90f4452c910caf674e6f1f9b90518,
                callback_address: hex"ae5d934a1d6107d7ca13f9e814de2ee148426743",
                callback_selector: 0x38ba4614,
                callback_gas_limit: 0x000186a0,
                packet_signature: hex"1a10a65cfbb7cea39add7ff786023a991a0d5f36adb0174f1d421aeb77baf03842dd9eda376861cc0da215af6921ed4e773a0d2c56f50e3d6b13fa17f66489af1c",
                result: hex"8db376ef68df62d2667dcb30932fe0e73307649df960f8f91961d409f944285c4ca3920b1cfc5c77a645af0417d12a12688c5f5a11e163f0330cc9273ddb15889e18d391586c3efaf8623837dbebcdc9658bff2dd88b3c399459fdb3e8d47952def3aad59e42bdc1f6208a2ff271d59e4b244e943f8ef52cb051e1db06d77f07c8f070a38632322a7721257b4f65cd95a52bfc41e111628701751c23f14bc4f33a8693389bf3b2f95532a78b8406ea93d8f1b2647480a7036cd4d0e750a647e0bacf05d544ea8f4c7e0e78c02077ad087eb2776152522e29ab55ca3ff46e177abb63edf770aeb805d379a0dbe505ef4737ba3f100b0ff43cfec9f740fd62eab4dfb72e1ca36f47cb8a9ac68afa45f9a0df1a1c237e00ecacc73b2e265db624c330575619a89be827694a948f0ea5e3c0f803f7f553c7e131f6759cd7fed28e1c4e127cbefda47c40aa0897486c3c0bc2337cb51f76acd4454d234d2809b9002202ede955a7d839fdaee29c80a1e6bfb77044b58bcd47ab9db75104262f02be76"
            });
        //postExecution(uint256 _taskId, string calldata _sourceNetwork, PostExecutionInfo calldata _info)
        gateway.postExecution(taskId, sourceNetwork, postExecutionInfo);

        vm.stopBroadcast();
    }
}
