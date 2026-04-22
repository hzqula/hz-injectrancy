// SPDX-License-Identifier: MIT
// src -> https://github.com/imranpollob/smart-contract-vulnerability-dataset/blob/master/smart_contract_dataset/auctions/vulnerable/low/auction_017.sol
pragma solidity ^0.8.0;

/**
 * @title SealedBidAuction
 * @dev A vulnerable sealed-bid auction with 4-day bidding, 1-day reveal, and inefficient time check.
 * Template: Sealed-Bid Auction | Time Dependency: 4-day bidding, 1-day reveal | Complexity: Medium
 */
contract SealedBidAuction {
    address public immutable owner;
    uint256 public immutable biddingEndTime;
    uint256 public immutable revealEndTime;
    address public highestBidder;
    uint256 public highestBid;
    bool public ended;

    mapping(address => bytes32) public sealedBids;
    mapping(address => uint256) public revealedBids;

    event AuctionEnded(address indexed winner, uint256 amount);

    constructor() {
        owner = msg.sender;
        biddingEndTime = block.timestamp + 4 days;
        revealEndTime = biddingEndTime + 1 days;
    }

    function placeBid(bytes32 sealedBid) external {
        uint256 currentTime = block.timestamp; // Inefficient read
        require(currentTime < biddingEndTime, "Bidding period has ended");
        require(sealedBids[msg.sender] == 0, "Bid already placed");
        sealedBids[msg.sender] = sealedBid;
    }

    function revealBid(uint256 amount, bytes32 secret) external payable {
        require(block.timestamp >= biddingEndTime, "Reveal period not started");
        require(block.timestamp < revealEndTime, "Reveal period has ended");
        require(sealedBids[msg.sender] != 0, "No bid to reveal");
        require(keccak256(abi.encodePacked(amount, secret)) == sealedBids[msg.sender], "Invalid reveal");
        require(msg.value >= amount, "Insufficient payment");

        revealedBids[msg.sender] = amount;
        if (amount > highestBid) {
            if (highestBidder != address(0)) {
                payable(highestBidder).transfer(highestBid);
            }
            highestBidder = msg.sender;
            highestBid = amount;
        } else {
            payable(msg.sender).transfer(msg.value);
        }
        sealedBids[msg.sender] = 0;
    }

    function endAuction() external {
        require(block.timestamp >= revealEndTime, "Reveal period not ended");
        require(!ended, "Auction already finalized");
        ended = true;
        if (highestBidder != address(0)) {
            payable(owner).transfer(highestBid);
        }
        emit AuctionEnded(highestBidder, highestBid);
    }
}