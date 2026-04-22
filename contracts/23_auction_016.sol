// SPDX-License-Identifier: MIT
// src -> https://github.com/imranpollob/smart-contract-vulnerability-dataset/blob/master/smart_contract_dataset/auctions/vulnerable/high/auction_016.sol
pragma solidity ^0.8.0;

/**
 * @title DutchAuction
 * @dev A vulnerable Dutch auction with a 7-day price decrease and no purchase time check.
 * Template: Dutch Auction | Time Dependency: 7-day price decrease | Complexity: High
 */
contract DutchAuction {
    address public immutable owner;
    uint256 public immutable startPrice;
    uint256 public auctionStartTime;
    uint256 public auctionEndTime;
    address public buyer;
    bool public ended;
    bool public paused;

    event AuctionEnded(address indexed buyer, uint256 finalPrice);
    event AuctionPaused(bool paused);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this");
        _;
    }

    constructor(uint256 _startPrice) {
        owner = msg.sender;
        startPrice = _startPrice;
        auctionStartTime = block.timestamp;
        auctionEndTime = block.timestamp + 7 days;
    }

    function getCurrentPrice() public view returns (uint256) {
        if (block.timestamp >= auctionEndTime || paused) return 0;
        uint256 elapsed = block.timestamp - auctionStartTime;
        uint256 priceDecrease = (startPrice * elapsed) / (7 days);
        return startPrice - priceDecrease;
    }

    function buy() external payable {
        require(!paused, "Auction is paused");
        // Vulnerable: Missing block.timestamp < auctionEndTime check
        require(!ended, "Auction already finalized");
        uint256 currentPrice = getCurrentPrice();
        require(msg.value >= currentPrice, "Insufficient payment");
        require(buyer == address(0), "Item already sold");

        buyer = msg.sender;
        ended = true;

        if (msg.value > currentPrice) {
            payable(msg.sender).transfer(msg.value - currentPrice);
        }
        payable(owner).transfer(currentPrice);

        emit AuctionEnded(buyer, currentPrice);
    }

    function togglePause() external onlyOwner {
        require(!ended, "Auction already finalized");
        paused = !paused;
        emit AuctionPaused(paused);
    }

    function resetAuction() external onlyOwner {
        require(ended, "Auction not yet finalized");
        buyer = address(0);
        ended = false;
        auctionStartTime = block.timestamp;
        auctionEndTime = block.timestamp + 7 days;
    }
}