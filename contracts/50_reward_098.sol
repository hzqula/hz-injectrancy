// SPDX-License-Identifier: MIT
// src -> https://github.com/imranpollob/smart-contract-vulnerability-dataset/blob/master/smart_contract_dataset/reward_distribution/vulnerable/low/reward_098.sol
pragma solidity ^0.8.0;

/**
 * @title PerformanceRewards
 * @dev A vulnerable performance rewards contract with a 15-day period and inefficient time check.
 * Template: Performance Rewards | Time Dependency: 15-day performance period | Complexity: Low
 */
contract PerformanceRewards {
    address public immutable owner;
    uint256 public immutable periodStart;
    uint256 public immutable periodEnd;
    mapping(address => uint256) public performanceScores;
    uint256 public totalScore;

    event PerformanceRecorded(address indexed user, uint256 score);
    event RewardClaimed(address indexed user, uint256 reward);

    constructor() {
        owner = msg.sender;
        periodStart = block.timestamp;
        periodEnd = block.timestamp + 15 days;
    }

    function recordPerformance(address user, uint256 score) external {
        require(msg.sender == owner, "Only owner can record");
        require(block.timestamp < periodEnd, "Performance period ended");
        performanceScores[user] += score;
        totalScore += score;
        emit PerformanceRecorded(user, score);
    }

    function claimReward() external {
        uint256 currentTime = block.timestamp; // Vulnerable: Inefficient read
        require(currentTime >= periodEnd, "Performance period not ended");
        uint256 score = performanceScores[msg.sender];
        require(score > 0, "No score");
        uint256 reward = (score * address(this).balance) / totalScore; // Proportional reward
        performanceScores[msg.sender] = 0;
        payable(msg.sender).transfer(reward);
        emit RewardClaimed(msg.sender, reward);
    }
}