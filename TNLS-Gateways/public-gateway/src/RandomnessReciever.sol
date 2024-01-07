// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

interface ISecretVRF {
    function requestRandomness(uint32 _numWords, uint32 _callbackGasLimit) external payable returns (uint256 requestId);
}

contract RandomnessReciever {

    address public VRFGateway;
    address public immutable owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "UNAUTHORIZED");
        _;
    }

    function setGatewayAddress(address _VRFGateway) external onlyOwner {
        VRFGateway = _VRFGateway;
    }


    function requestRandomnessTest() external {
        uint32 numWords = 2000; // can be up to 2000 words
        uint32 callbackGasLimit = 2000000;   
        ISecretVRF vrfContract = ISecretVRF(VRFGateway);
        uint256 requestId = vrfContract.requestRandomness(numWords, callbackGasLimit);
    }

    event fulfilledRandomWords(uint256 requestId, uint256[] randomWords);

    /*//////////////////////////////////////////////////////////////
                   fulfillRandomWords Callback
    //////////////////////////////////////////////////////////////*/

    function fulfillRandomWords(uint256 requestId, uint256[] calldata randomWords) external {
        require(msg.sender == address(VRFGateway), "only Secret Gateway can fulfill");
        //do your custom stuff here.
        emit fulfilledRandomWords(requestId, randomWords);
    }
}