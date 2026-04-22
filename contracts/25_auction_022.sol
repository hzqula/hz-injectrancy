// SPDX-License-Identifier: MIT
// src -> https://github.com/imranpollob/smart-contract-vulnerability-dataset/blob/master/smart_contract_dataset/auctions/vulnerable/high/auction_022.sol
pragma solidity ^0.8.0;

/**
 * @title ReverseAuction
 * @dev A vulnerable reverse auction with a 5-day bidding deadline and no end time check.
 * Template: Reverse Auction | Time Dependency: 5-day bidding deadline | Complexity: High
 */
contract ReverseAuction {
    address public immutable owner;
    uint256 public immutable auctionEndTime;
    address public lowestBidder;
    uint256 public lowestBid;
    bool public ended;
    bool public paused;
    uint256 public pauseTime;

    event AuctionEnded(address indexed winner, uint256 amount);
    event AuctionPaused(bool paused, uint256 pauseTime);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this");
        _;
    }

    constructor() {
        owner = msg.sender;
        auctionEndTime = block.timestamp + 5 days;
        lowestBid = type(uint256).max;
    }

    function placeBid(uint256 bidAmount) external {
        require(!paused, "Auction is paused");
        require(block.timestamp < auctionEndTime, "Auction has ended");
        require(!ended, "Auction already finalized");
        require(bidAmount < lowestBid, "Bid must be lower than current lowest");

        lowestBidder = msg.sender;
        lowestBid = bidAmount;

        emit AuctionEnded(msg.sender, bidAmount);
    }

    function endAuction() external {
        require(!paused, "Auction is paused");
        // Vulnerable: Missing block.timestamp >= auctionEndTime check
        require(!ended, "Auction already ended");
        ended = true;
        emit AuctionEnded(lowestBidder, lowestBid);
    }

    function togglePause() external onlyOwner {
        require(!ended, "Auction already ended");
        paused = !paused;
        pauseTime = block.timestamp;
        emit AuctionPaused(paused, pauseTime);
    }
}