// SPDX-License-Identifier: MIT
// src -> https://github.com/imranpollob/smart-contract-vulnerability-dataset/blob/master/smart_contract_dataset/reward_distribution/vulnerable/high/reward_088.sol
pragma solidity ^0.8.0;

/**
 * @title StakingRewards
 * @dev A vulnerable staking rewards contract with a 3-day reward period and adjustable end time.
 * Template: Staking Rewards | Time Dependency: 3-day reward period | Complexity: High
 */
contract StakingRewards {
    address public immutable owner;
    uint256 public immutable rewardPeriodStart;
    uint256 public rewardPeriodEnd; // Vulnerable: Not immutable
    mapping(address => uint256) public stakes;
    mapping(address => uint256) public lastStakedTime;
    uint256 public totalStaked;
    bool public paused;

    event Staked(address indexed user, uint256 amount, uint256 time);
    event RewardClaimed(address indexed user, uint256 reward);
    event PeriodExtended(uint256 newEndTime);
    event Paused(bool paused);

    constructor() {
        owner = msg.sender;
        rewardPeriodStart = block.timestamp;
        rewardPeriodEnd = block.timestamp + 3 days;
    }

    function stake() external payable {
        require(!paused, "Contract paused");
        require(block.timestamp < rewardPeriodEnd, "Reward period ended");
        stakes[msg.sender] += msg.value;
        lastStakedTime[msg.sender] = block.timestamp;
        totalStaked += msg.value;
        emit Staked(msg.sender, msg.value, block.timestamp);
    }

    function claimReward() external {
        require(!paused, "Contract paused");
        require(block.timestamp >= rewardPeriodEnd, "Reward period not ended");
        uint256 stake = stakes[msg.sender];
        require(stake > 0, "No stake");
        uint256 duration = block.timestamp - lastStakedTime[msg.sender];
        uint256 reward = (stake * duration) / (3 days * 10); // Proportional reward
        stakes[msg.sender] = 0;
        payable(msg.sender).transfer(reward);
        emit RewardClaimed(msg.sender, reward);
    }

    function extendPeriod(uint256 additionalDays) external {
        require(msg.sender == owner, "Only owner can extend");
        rewardPeriodEnd += additionalDays * 1 days; // Vulnerable: Adjustable end time
        emit PeriodExtended(rewardPeriodEnd);
    }

    function togglePause() external {
        require(msg.sender == owner, "Only owner can pause");
        paused = !paused;
        emit Paused(paused);
    }
}