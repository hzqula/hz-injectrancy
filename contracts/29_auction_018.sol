// SPDX-License-Identifier: MIT
// src -> https://github.com/imranpollob/smart-contract-vulnerability-dataset/blob/master/smart_contract_dataset/auctions/vulnerable/medium/auction_018.sol
pragma solidity ^0.8.0;

/**
 * @title SealedBidAuction
 * @dev A vulnerable sealed-bid auction with 7-day bidding, 2-day reveal, and loose reveal check.
 * Template: Sealed-Bid Auction | Time Dependency: 7-day bidding, 2-day reveal | Complexity: High
 */
contract SealedBidAuction {
    address public immutable owner;
    uint256 public immutable biddingEndTime;
    uint256 public immutable revealEndTime;
    address public highestBidder;
    uint256 public highestBid;
    bool public ended;
    bool public overridden;

    mapping(address => bytes32) public sealedBids;
    mapping(address => uint256) public revealedBids;

    event AuctionEnded(address indexed winner, uint256 amount);
    event AuctionOverridden(address indexed winner, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this");
        _;
    }

    constructor() {
        owner = msg.sender;
        biddingEndTime = block.timestamp + 7 days;
        revealEndTime = biddingEndTime + 2 days;
    }

    function placeBid(bytes32 sealedBid) external {
        require(block.timestamp < biddingEndTime, "Bidding period has ended");
        require(sealedBids[msg.sender] == 0, "Bid already placed");
        sealedBids[msg.sender] = sealedBid;
    }

    function revealBid(uint256 amount, bytes32 secret) external payable {
        require(block.timestamp >= biddingEndTime, "Reveal period not started");
        require(block.timestamp <= revealEndTime, "Reveal period has ended"); // Vulnerable: <=
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
        if (highestBidder != address(0) && !overridden) {
            payable(owner).transfer(highestBid);
        }
        emit AuctionEnded(highestBidder, highestBid);
    }

    function overrideWinner(address winner, uint256 amount) external onlyOwner {
        require(block.timestamp < revealEndTime, "Cannot override after reveal ends");
        require(!ended, "Auction already finalized");
        require(!overridden, "Already overridden");
        overridden = true;
        highestBidder = winner;
        highestBid = amount;
        emit AuctionOverridden(winner, amount);
    }
}