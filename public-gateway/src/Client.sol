// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import {Util} from "../src/Util.sol";
import {IGateway} from "../src/interfaces/IGateway.sol";
import "../src/interfaces/IClient.sol";

contract Client is IClient {
    using Util for *;

    /// @notice Emitted when we recieve callback for our result of the computation
    event ComputedResult(uint256 indexed taskId, bytes result);

    /*//////////////////////////////////////////////////////////////
                             Constructor
    //////////////////////////////////////////////////////////////*/

    address public GatewayAddress;

    constructor(address _gatewayAddress) {
        GatewayAddress = _gatewayAddress;
    }

    modifier onlyGateway() {
        require(msg.sender == GatewayAddress, "Only Gateway contract can call this method");
        _;
    }

    /*//////////////////////////////////////////////////////////////
                        New Task and Send Call
    //////////////////////////////////////////////////////////////*/

    function newTask(
        address _callbackAddress,
        bytes4 _callbackSelector,
        address _userAddress,
        string memory _sourceNetwork,
        string memory _routingInfo,
        bytes32 _payloadHash
    )
        internal
        pure
        returns (Util.Task memory)
    {
        return Util.Task(_callbackAddress, _callbackSelector, _userAddress, _sourceNetwork, _routingInfo, _payloadHash, false);
    }

    /// @param _userAddress  User address
    /// @param _sourceNetwork Source network of msg
    /// @param _routingInfo Routing info for computation
    /// @param _payloadHash Payload hash
    /// @param _info ExecutionInfo struct
    function send(
        address _userAddress,
        string memory _sourceNetwork,
        string memory _routingInfo,
        bytes32 _payloadHash,
        Util.ExecutionInfo memory _info
    )
        public
    {
        Util.Task memory newtask;

        newtask = newTask(address(this), this.callback.selector, _userAddress, _sourceNetwork, _routingInfo, _payloadHash);

        IGateway(GatewayAddress).preExecution(newtask, _info);
    }

    /*//////////////////////////////////////////////////////////////
                               Callback
    //////////////////////////////////////////////////////////////*/

    /// @param _taskId  Task Id of the computation
    /// @param _result computed result
    /// @param _result The second stored number input
    function callback(uint256 _taskId, bytes memory _result) external onlyGateway {
        emit ComputedResult(_taskId, _result);
    }
}
