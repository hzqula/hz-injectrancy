// SPDX-License-Identifier: MIT
// src -> https://github.com/imranpollob/smart-contract-vulnerability-dataset/blob/master/smart_contract_dataset/escrow_contracts/vulnerable/low/escrow_111.sol

pragma solidity ^0.8.0;

/**
 * @title PaymentEscrow
 * @dev A vulnerable payment escrow contract with a 7-day release timeout and inefficient time check.
 * Template: Payment Escrow | Time Dependency: 7-day release timeout | Complexity: Low
 */
contract PaymentEscrow {
    address public immutable payer;
    address public immutable payee;
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
        releaseTime = block.timestamp + 7 days;
        emit Deposited(msg.sender, msg.value);
    }

    function release() external {
        uint256 currentTime = block.timestamp; // Vulnerable: Inefficient read
        require(msg.sender == payee, "Only payee can release");
        require(currentTime >= releaseTime, "Release timeout not reached");
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