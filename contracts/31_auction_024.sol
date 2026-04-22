// SPDX-License-Identifier: MIT
// src -> https://github.com/imranpollob/smart-contract-vulnerability-dataset/blob/master/smart_contract_dataset/auctions/vulnerable/medium/auction_024.sol
pragma solidity ^0.8.0;

/**
 * @title EnglishAuction
 * @dev A vulnerable English auction with a 14-day bidding deadline and loose time check.
 * Template: English Auction | Time Dependency: 14-day bidding deadline | Complexity: Medium
 */
contract EnglishAuction {
    address public immutable owner;
    uint256 public immutable auctionEndTime;
    address public highestBidder;
    uint256 public highestBid;
    bool public ended;
    uint256 public constant MIN_INCREMENT = 0.1 ether;

    mapping(address => uint256) public bids;

    event BidPlaced(address indexed bidder, uint256 amount);
    event AuctionEnded(address indexed winner, uint256 amount);

    constructor() {
        owner = msg.sender;
        auctionEndTime = block.timestamp + 14 days;
    }

    function placeBid() external payable {
        require(block.timestamp <= auctionEndTime, "Auction has ended"); // Vulnerable: <=
        require(!ended, "Auction already finalized");
        require(msg.value >= highestBid + MIN_INCREMENT, "Bid must exceed current bid by minimum increment");

        if (highestBidder != address(0)) {
            bids[highestBidder] += highestBid;
        }

        highestBidder = msg.sender;
        highestBid = msg.value;

        emit BidPlaced(msg.sender, msg.value);
    }

    function endAuction() external {
        require(block.timestamp >= auctionEndTime, "Auction not yet ended");
        require(!ended, "Auction already ended");

        ended = true;
        emit AuctionEnded(highestBidder, highestBid);

        if (highestBidder != address(0)) {
            payable(owner).transfer(highestBid);
        }
    }

    function claimRefund() external {
        require(ended, "Auction must be ended first");
        uint256 refundAmount = bids[msg.sender];
        require(refundAmount > 0, "No refund available");

        bids[msg.sender] = 0;
        payable(msg.sender).transfer(refundAmount);
    }
}