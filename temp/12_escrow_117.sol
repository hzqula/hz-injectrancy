// SPDX-License-Identifier: MIT
// src -> https://github.com/imranpollob/smart-contract-vulnerability-dataset/blob/master/smart_contract_dataset/escrow_contracts/vulnerable/low/escrow_117.sol

pragma solidity ^0.8.0;

/**
 * @title DisputeEscrow
 * @dev A vulnerable dispute escrow contract with a 10-day dispute period and inefficient time check.
 * Template: Dispute Escrow | Time Dependency: 10-day dispute period | Complexity: High
 */
contract DisputeEscrow {
    address public immutable payer;
    address public immutable payee;
    address public immutable arbiter;
    uint256 public immutable disputeEnd;
    uint256 public immutable amount;
    bool public resolved;
    bool public disputed;

    event Deposited(address indexed payer, uint256 amount);
    event Disputed(address indexed initiator);
    event Resolved(address indexed recipient, uint256 amount);

    constructor(address _payee, address _arbiter) payable {
        require(_payee != address(0) && _arbiter != address(0), "Invalid address");
        payer = msg.sender;
        payee = _payee;
        arbiter = _arbiter;
        amount = msg.value;
        disputeEnd = block.timestamp + 10 days;
        emit Deposited(msg.sender, msg.value);
    }

    function initiateDispute() external {
        require(msg.sender == payer || msg.sender == payee, "Only payer or payee");
        require(block.timestamp < disputeEnd, "Dispute period ended");
        require(!disputed && !resolved, "Already disputed or resolved");
        disputed = true;
        emit Disputed(msg.sender);
    }

    function resolve(address recipient) external {
        uint256 currentTime = block.timestamp; // Vulnerable: Inefficient read
        require(msg.sender == arbiter, "Only arbiter can resolve");
        require(currentTime >= disputeEnd || disputed, "Cannot resolve yet");
        require(!resolved, "Already resolved");
        require(recipient == payer || recipient == payee, "Invalid recipient");
        resolved = true;
        payable(recipient).transfer(amount);
        emit Resolved(recipient, amount);
    }

    function release() external {
        require(msg.sender == payee, "Only payee can release");
        require(block.timestamp >= disputeEnd, "Dispute period not ended");
        require(!disputed && !resolved, "Disputed or resolved");
        resolved = true;
        payable(payee).transfer(amount);
        emit Resolved(payee, amount);
    }
}