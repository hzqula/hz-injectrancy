
// src -> https://sepolia.etherscan.io/address/0x900a5f51b199eaed962a19f4214953aa2e59b8ca#code

// File: @chainlink/contracts/src/v0.8/shared/interfaces/AggregatorV3Interface.sol


pragma solidity ^0.8.0;

// solhint-disable-next-line interface-starts-with-i
interface AggregatorV3Interface {
  function decimals() external view returns (uint8);

  function description() external view returns (string memory);

  function version() external view returns (uint256);

  function getRoundData(
    uint80 _roundId
  ) external view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);

  function latestRoundData()
    external
    view
    returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}

// File: contracts/PriceConverter.sol


pragma solidity ^0.8.23;


library PriceConverter {
    // ETHUSD PRICEFEED ON SEPOLIA => 0x694AA1769357215DE4FAC081bf1f309aDC325306

    function getConversionRate(uint256 _ethValueToConvert, address _priceFeedAddress) internal view returns(uint256) {
        uint256 price = getPrice(_priceFeedAddress);
        uint256 receivedValueInUSD = _ethValueToConvert * (price * 10 ** 10);
        return receivedValueInUSD;
    }

    function getPrice(address _priceFeedAddress) internal view returns(uint256) {
        AggregatorV3Interface priceFeedContract = AggregatorV3Interface(_priceFeedAddress);
        (,int answer,,,) = priceFeedContract.latestRoundData();
        uint256 price = uint256(answer);
        return price;
    }

    
}
// File: contracts/05_FundMe.sol


pragma solidity ^0.8.23;


contract FundMe {

    using PriceConverter for uint256;

    uint256 constant MINIMUM_ALLOWED_VALUE = 5e18;
    address immutable  PRICE_FEED_ADDRESS;
    address payable immutable  i_owner; 

    address[] private s_funders;
    mapping(address funder => uint256 amount) private s_addressToAmountFunded;

    constructor(address  _priceFeedAddress) {
        PRICE_FEED_ADDRESS = _priceFeedAddress;
        i_owner = payable(msg.sender);
    }

    function fund() public payable {
        uint256 receivedValueInUSD = msg.value.getConversionRate(PRICE_FEED_ADDRESS);
        require(receivedValueInUSD >= MINIMUM_ALLOWED_VALUE, "You didn't send enough ether");
        s_funders.push(msg.sender);
        s_addressToAmountFunded[msg.sender] += msg.value; 
    }

    function withdraw() public {
        require(msg.sender == i_owner, "You are not the owner of the contract");
        uint256 fundersLength = s_funders.length;
        for(uint256 index; index < fundersLength; index++){
            address currentAddress = s_funders[index];
            s_addressToAmountFunded[currentAddress] = 0;
        }
        s_funders = new address[](0);
        (bool callSuccess, ) = i_owner.call{value: address(this).balance}("");
        require(callSuccess == true, "Sending ether to owner failed");
    }

    function getOwner() external view returns(address) {
        return i_owner;
    }

    function getPriceFeedVersion() external view returns(uint256) {
        return AggregatorV3Interface(PRICE_FEED_ADDRESS).version();
    }

    function getAddressToAmountFunded(address _address) external view returns(uint256) {
        return s_addressToAmountFunded[_address];
    }

    function getAddressAtIndex(uint256 _index) external view returns(address) {
        return s_funders[_index];
    }

    receive() external payable  {
        fund();
    }

    fallback() external payable { 
        fund();
    }
}

// 00000000000000000000000000000000000000000000000000000000000000ff
// 00000000000000000000000000000000000000000000000000000000000000ff