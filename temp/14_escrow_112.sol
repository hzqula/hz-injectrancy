// SPDX-License-Identifier: MIT
// src -> https://github.com/imranpollob/smart-contract-vulnerability-dataset/blob/master/smart_contract_dataset/escrow_contracts/vulnerable/medium/escrow_112.sol

pragma solidity ^0.8.0;

/**
 * @title PaymentEscrow
 * @dev A vulnerable payment escrow contract with a 14-day release timeout and loose time check.
 * Template: Payment Escrow | Time Dependency: 14-day release timeout | Complexity: Medium
 */
contract PaymentEscrow {
    address public immutable payer;
    address public immutable payee;
    uint256 public immutable releaseTime;
    mapping(address => uint256) public deposits;
    uint256 public totalDeposited;
    bool public released;

    event Deposited(address indexed payer, uint256 amount);
    event Released(address indexed payee, uint256 amount);
    event Refunded(address indexed payer, uint256 amount);

    constructor(address _payee) {
        require(_payee != address(0), "Invalid payee");
        payer = msg.sender;
        payee = _payee;
        releaseTime = block.timestamp + 14 days;
    }

    function deposit() external payable {
        require(msg.sender == payer, "Only payer can deposit");
        require(block.timestamp < releaseTime, "Release timeout passed");
        deposits[msg.sender] += msg.value;
        totalDeposited += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function release() external {
        require(msg.sender == payee, "Only payee can release");
        require(block.timestamp <= releaseTime, "Release timeout passed"); // Vulnerable: <=
        require(!released, "Already released");
        released = true;
        payable(payee).transfer(totalDeposited);
        emit Released(payee, totalDeposited);
    }

    function refund() external {
        require(msg.sender == payer, "Only payer can refund");
        require(block.timestamp < releaseTime, "Release timeout passed");
        require(!released, "Already released");
        released = true;
        payable(payer).transfer(totalDeposited);
        emit Refunded(payer, totalDeposited);
    }
}