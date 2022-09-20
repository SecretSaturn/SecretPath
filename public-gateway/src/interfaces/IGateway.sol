// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import {Util} from "../Util.sol";

interface IGateway {
    function initialize(address _masterVerificationAddress) external;

    function updateRoute(string memory _route, address _verificationAddress, bytes memory _signature) external;

    function preExecution(Util.Task memory _task, Util.ExecutionInfo memory _info) external;

    function postExecution(uint256 _taskId, string memory _sourceNetwork, Util.PostExecutionInfo memory _info) external;
}
