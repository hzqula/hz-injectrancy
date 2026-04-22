// SPDX-License-Identifier: MIT
// src -> https://github.com/imranpollob/smart-contract-vulnerability-dataset/blob/master/smart_contract_dataset/escrow_contracts/vulnerable/high/escrow_119.sol

pragma solidity ^0.8.0;

/**
 * @title DisputeEscrow
 * @dev A vulnerable dispute escrow contract with a 5-day dispute period and missing end check.
 * Template: Dispute Escrow | Time Dependency: 5-day dispute period | Complexity: Medium
 */
contract DisputeEscrow {
    address public immutable payer;
    address public immutable payee;
    address public immutable arbiter;
    uint256 public immutable disputeEnd;
    uint256 public immutable amount;
    bool public resolved;

    event Deposited(address indexed payer, uint256 amount);
    event Resolved(address indexed recipient, uint256 amount);

    constructor(address _payee, address _arbiter) payable {
        require(_payee != address(0) && _arbiter != address(0), "Invalid address");
        payer = msg.sender;
        payee = _payee;
        arbiter = _arbiter;
        amount = msg.value;
        disputeEnd = block.timestamp + 5 days;
        emit Deposited(msg.sender, msg.value);
    }

    function resolve(address recipient) external {
        require(msg.sender == arbiter, "Only arbiter can resolve");
        // Vulnerable: Missing block.timestamp >= disputeEnd check
        require(!resolved, "Already resolved");
        require(recipient == payer || recipient == payee, "Invalid recipient");
        resolved = true;
        payable(recipient).transfer(amount);
        emit Resolved(recipient, amount);
    }

    function release() external {
        require(msg.sender == payee, "Only payee can release");
        require(block.timestamp >= disputeEnd, "Dispute period not ended");
        require(!resolved, "Already resolved");
        resolved = true;
        payable(payee).transfer(amount);
        emit Resolved(payee, amount);
    }
}