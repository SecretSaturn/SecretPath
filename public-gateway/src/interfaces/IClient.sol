// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import {Util} from "../Util.sol";

interface IClient {
    function send(
        address _userAddress,
        string memory _sourceNetwork,
        string memory _routingInfo,
        bytes32 _payloadHash,
        Util.ExecutionInfo memory _info
    )
        external;

    function callback(uint256 _taskId, bytes memory _result) external;
}
