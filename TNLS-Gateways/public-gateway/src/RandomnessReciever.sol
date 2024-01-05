// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

contract RandomnessReciever {

    address private RNGGateway;
    address private immutable owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "UNAUTHORIZED");
        _;
    }

    function setGatewayAddress(address _RNGGateway) external onlyOwner {
        RNGGateway = _RNGGateway;
    }


    function requestRandomWordsTest() external {
        bool success;
        bytes memory data;
        uint256 requestId;
        uint32 numWords = 50; // can be up to 50 words
        uint32 callbackGasLimit = 1000000;   
        (success, data) = RNGGateway.call(abi.encodeWithSelector(bytes4(0x967b2017), numWords, callbackGasLimit));
        require(success, "External call failed");
        if (data.length == 32) {
            assembly {requestId := mload(add(data, 32))}
        } else {
            revert("Data returned is too short");
        }
    }

    event fulfilledRandomWords(uint256 requestId, uint256[] randomWords);

    /*//////////////////////////////////////////////////////////////
                               Callback
    //////////////////////////////////////////////////////////////*/

    function fulfillRandomWords(uint256 requestId, uint256[] memory randomWords) external {
        require(msg.sender == address(RNGGateway), "only Secret Gateway can fulfill");
        //do your custom stuff here.
        emit fulfilledRandomWords(requestId, randomWords);
    }
}