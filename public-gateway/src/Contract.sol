// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

contract Gateway {
    /*//////////////////////////////////////////////////////////////
                             Constructor
    //////////////////////////////////////////////////////////////*/

    address private owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this method");
        _;
    }

    /*//////////////////////////////////////////////////////////////
                             Initialization
    //////////////////////////////////////////////////////////////*/

    address masterVerificationAddress;

    /// @notice Initialize the verification address
    /// @param _masterVerificationAddress The input address
    function initialize(address _masterVerificationAddress) public onlyOwner {
        masterVerificationAddress = _masterVerificationAddress;
    }

    /*//////////////////////////////////////////////////////////////
                             Update Routes
    //////////////////////////////////////////////////////////////*/

    /// @notice Updating the Routes
    /// @param _routes List of routes
    /// @param _verificationKeys List of keys corresponding to the routes
    /// @param _num Number of route pairs
    function updateRoutes(
        string[] memory _routes,
        bytes32[] memory _verificationKeys,
        uint256 _num
    ) public onlyOwner {
        // ?? are the signature going to be for the individual routes or whole payload
        // Parse out and create the mapping of the values
    }

    /*//////////////////////////////////////////////////////////////
                             Pre Execution
    //////////////////////////////////////////////////////////////*/

    /// @notice Pre-Execution
    /// @param _handle handle for routing
    /// @param _contractAddress contract address for routing
    /// @param _inputs inputs provided for the execution
    /// @param _callback callback for the sorce destination
    /// @param _signature signature of params
    function preExecution() public onlyOwner {
        // is the signature just for the inputs or any other data attached to it ?
        // what is a _handle ?
    }

    /*//////////////////////////////////////////////////////////////
                             Post Execution
    //////////////////////////////////////////////////////////////*/

    /// @notice Post-Execution
    /// @param _outputs Outputs from the private execution
    /// @param _data task ID+input pair
    /// @param _signature signature of params
    /// @param _sourceNetwork
    function postExecution() public onlyOwner {}
}
