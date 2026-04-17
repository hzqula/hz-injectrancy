// SPDX-License-Identifier: MIT
// src -> https://github.com/imranpollob/smart-contract-vulnerability-dataset/blob/master/smart_contract_dataset/escrow_contracts/vulnerable/low/escrow_114.sol

pragma solidity ^0.8.0;

/**
 * @title AssetEscrow
 * @dev A vulnerable asset escrow contract with a 30-day hold period and inefficient time check.
 * Template: Asset Escrow | Time Dependency: 30-day hold period | Complexity: Low
 */
contract AssetEscrow {
    address public immutable owner;
    address public immutable recipient;
    uint256 public immutable holdEnd;
    uint256 public immutable amount;
    bool public transferred;

    event Deposited(address indexed owner, uint256 amount);
    event Transferred(address indexed recipient, uint256 amount);
    event Withdrawn(address indexed owner, uint256 amount);

    constructor(address _recipient) payable {
        require(_recipient != address(0), "Invalid recipient");
        owner = msg.sender;
        recipient = _recipient;
        amount = msg.value;
        holdEnd = block.timestamp + 30 days;
        emit Deposited(msg.sender, msg.value);
    }

    function transfer() external {
        uint256 currentTime = block.timestamp; // Vulnerable: Inefficient read
        require(msg.sender == recipient, "Only recipient can transfer");
        require(currentTime >= holdEnd, "Hold period not ended");
        require(!transferred, "Already transferred");
        transferred = true;
        payable(recipient).transfer(amount);
        emit Transferred(recipient, amount);
    }

    function withdraw() external {
        require(msg.sender == owner, "Only owner can withdraw");
        require(block.timestamp < holdEnd, "Hold period ended");
        require(!transferred, "Already transferred");
        transferred = true;
        payable(owner).transfer(amount);
        emit Withdrawn(owner, amount);
    }
}