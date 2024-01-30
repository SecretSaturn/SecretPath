// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;


/// @notice Interface of the VRF Gateway contract. Must be imported.
interface ISecretVRF {
    function requestRandomness(uint32 _numWords, uint32 _callbackGasLimit) external payable returns (uint256 requestId);
}

contract RandomnessReciever {

    /// @notice VRFGateway stores address to the Gateway contract to call for VRF
    address public VRFGateway;

    address public immutable owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "UNAUTHORIZED");
        _;
    }

    /// @notice Sets the address to the Gateway contract 
    /// @param _VRFGateway address of the gateway
    function setGatewayAddress(address _VRFGateway) external onlyOwner {
        VRFGateway = _VRFGateway;
    }

    /// @notice Event that is emitted when a VRF call was made (optional)
    /// @param requestId requestId of the VRF request. Contract can track a VRF call that way
    event requestedRandomness(uint256 requestId);

    /// @notice Demo function on how to implement a VRF call using Secret VRF
    function requestRandomnessTest(uint32 _numWords, uint32 _callbackGasLimit) external payable {
        // Get the VRFGateway contract interface 
        ISecretVRF vrfContract = ISecretVRF(VRFGateway);

        // Call the VRF contract to request random numbers. 
        // Returns requestId of the VRF request. A contract can track a VRF call that way.
        uint256 requestId = vrfContract.requestRandomness{value: msg.value}(_numWords, _callbackGasLimit);

        // Emit the event
        emit requestedRandomness(requestId);
    }

    /// @notice Demo function on how to implement a VRF call using Secret VRF, here the values for numWords and callbackGasLimit are preset
    function requestRandomnessTestPreset() external payable {
        // Can be up to 2000 random numbers, change this according to your needs
        uint32 numWords = 20; 

        // Change callbackGasLimit according to your needs for post processing in your callback
        uint32 callbackGasLimit = 300000; 

        // Get the VRFGateway contract interface 
        ISecretVRF vrfContract = ISecretVRF(VRFGateway);

        // Call the VRF contract to request random numbers. 
        // Returns requestId of the VRF request. A  contract can track a VRF call that way.
        uint256 requestId = vrfContract.requestRandomness{value: msg.value}(numWords, callbackGasLimit);

        // Emit the event
        emit requestedRandomness(requestId);
    }

    /*//////////////////////////////////////////////////////////////
                   fulfillRandomWords Callback
    //////////////////////////////////////////////////////////////*/

    event fulfilledRandomWords(uint256 requestId, uint256[] randomWords);

    /// @notice Callback by the Secret VRF with the requested random numbers
    /// @param requestId requestId of the VRF request that was initally called
    /// @param randomWords Generated Random Numbers in uint256 array
    function fulfillRandomWords(uint256 requestId, uint256[] calldata randomWords) external {
        // Checks if the callback was called by the VRFGateway and not by any other address
        require(msg.sender == address(VRFGateway), "only Secret Gateway can fulfill");

        // Do your custom stuff here, for example:
        emit fulfilledRandomWords(requestId, randomWords);
    }
}