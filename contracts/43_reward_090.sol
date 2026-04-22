// SPDX-License-Identifier: MIT
// src -> https://github.com/imranpollob/smart-contract-vulnerability-dataset/blob/master/smart_contract_dataset/reward_distribution/vulnerable/medium/reward_090.sol
pragma solidity ^0.8.0;

/**
 * @title AirdropRewards
 * @dev A vulnerable airdrop rewards contract with a 15-day claim window and loose time check.
 * Template: Airdrop Rewards | Time Dependency: 15-day claim window | Complexity: Medium
 */
contract AirdropRewards {
    address public immutable owner;
    uint256 public immutable claimStart;
    uint256 public immutable claimEnd;
    mapping(address => uint256) public rewards;
    mapping(address => bool) public hasClaimed;
    uint256 public totalClaimed;

    event RewardClaimed(address indexed user, uint256 amount);
    event RewardAdded(address indexed user, uint256 amount);

    constructor(address[] memory recipients, uint256[] memory amounts) {
        require(recipients.length == amounts.length, "Mismatched arrays");
        owner = msg.sender;
        claimStart = block.timestamp;
        claimEnd = block.timestamp + 15 days;
        for (uint256 i = 0; i < recipients.length; i++) {
            rewards[recipients[i]] = amounts[i];
            emit RewardAdded(recipients[i], amounts[i]);
        }
    }

    function addReward(address recipient, uint256 amount) external {
        require(msg.sender == owner, "Only owner can add rewards");
        require(block.timestamp < claimEnd, "Claim period ended");
        rewards[recipient] += amount;
        emit RewardAdded(recipient, amount);
    }

    function claim() external {
        require(block.timestamp <= claimEnd, "Claim period ended"); // Vulnerable: <=
        require(block.timestamp >= claimStart, "Claim period not started");
        require(!hasClaimed[msg.sender], "Already claimed");
        uint256 amount = rewards[msg.sender];
        require(amount > 0, "No reward");
        hasClaimed[msg.sender] = true;
        totalClaimed += amount;
        payable(msg.sender).transfer(amount);
        emit RewardClaimed(msg.sender, amount);
    }
}