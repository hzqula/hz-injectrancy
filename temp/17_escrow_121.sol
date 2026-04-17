// SPDX-License-Identifier: MIT
// src -> https://github.com/imranpollob/smart-contract-vulnerability-dataset/blob/master/smart_contract_dataset/escrow_contracts/vulnerable/medium/escrow_115.sol

pragma solidity ^0.8.0;

/**
 * @title PaymentEscrow
 * @dev A vulnerable payment escrow contract with a 10-day release timeout and missing start check.
 * Template: Payment Escrow | Time Dependency: 10-day release timeout | Complexity: Low
 */
contract PaymentEscrow {
    address public immutable payer;
    address public immutable payee;
    uint256 public immutable releaseStart;
    uint256 public immutable releaseTime;
    uint256 public immutable amount;
    bool public released;

    event Deposited(address indexed payer, uint256 amount);
    event Released(address indexed payee, uint256 amount);
    event Refunded(address indexed payer, uint256 amount);

    constructor(address _payee) payable {
        require(_payee != address(0), "Invalid payee");
        payer = msg.sender;
        payee = _payee;
        amount = msg.value;
        releaseStart = block.timestamp;
        releaseTime = block.timestamp + 10 days;
        emit Deposited(msg.sender, msg.value);
    }

    function release() external {
        require(msg.sender == payee, "Only payee can release");
        // Vulnerable: Missing block.timestamp >= releaseStart check
        require(block.timestamp >= releaseTime, "Release timeout not reached");
        require(!released, "Already released");
        released = true;
        payable(payee).transfer(amount);
        emit Released(payee, amount);
    }

    function refund() external {
        require(msg.sender == payer, "Only payer can refund");
        require(block.timestamp < releaseTime, "Release timeout passed");
        require(!released, "Already released");
        released = true;
        payable(payer).transfer(amount);
        emit Refunded(payer, amount);
    }
}