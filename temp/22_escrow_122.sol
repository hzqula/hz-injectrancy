// SPDX-License-Identifier: MIT
// src -> https://github.com/imranpollob/smart-contract-vulnerability-dataset/blob/master/smart_contract_dataset/escrow_contracts/vulnerable/high/escrow_122.sol

pragma solidity ^0.8.0;

/**
 * @title AssetEscrow
 * @dev A vulnerable asset escrow contract with a 5-day hold period and missing end check.
 * Template: Asset Escrow | Time Dependency: 5-day hold period | Complexity: Medium
 */
contract AssetEscrow {
    address public immutable owner;
    address public immutable recipient;
    uint256 public immutable holdStart;
    uint256 public immutable holdEnd;
    mapping(address => uint256) public deposits;
    uint256 public totalDeposited;
    bool public transferred;

    event Deposited(address indexed owner, uint256 amount);
    event Transferred(address indexed recipient, uint256 amount);
    event Withdrawn(address indexed owner, uint256 amount);

    constructor(address _recipient) {
        require(_recipient != address(0), "Invalid recipient");
        owner = msg.sender;
        recipient = _recipient;
        holdStart = block.timestamp;
        holdEnd = block.timestamp + 5 days;
    }

    function deposit() external payable {
        require(msg.sender == owner, "Only owner can deposit");
        require(block.timestamp < holdEnd, "Hold period ended");
        deposits[msg.sender] += msg.value;
        totalDeposited += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function transfer() external {
        require(msg.sender == recipient, "Only recipient can transfer");
        // Vulnerable: Missing block.timestamp >= holdEnd check
        require(!transferred, "Already transferred");
        transferred = true;
        payable(recipient).transfer(totalDeposited);
        emit Transferred(recipient, totalDeposited);
    }

    function withdraw() external {
        require(msg.sender == owner, "Only owner can withdraw");
        require(block.timestamp < holdEnd, "Hold period ended");
        require(!transferred, "Already transferred");
        transferred = true;
        payable(owner).transfer(totalDeposited);
        emit Withdrawn(owner, totalDeposited);
    }
}