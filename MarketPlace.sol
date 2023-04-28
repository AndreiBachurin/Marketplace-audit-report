// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";


interface IRewardToken is IERC20 {
    function rewardUser(address owner, uint256 amount) external;
}


contract Rewardable {
    using SafeMath for uint256;

    error NothingForClaim();

    struct Reward {
        uint256 timestamp;
        uint256 amount;
    }

    uint256 constant public PCT_DENOMINATOR = 1000;

    uint256 private constant SEED = 335813536577843457;
    IERC20 internal PAYMENT_TOKEN;
    IRewardToken internal REWARD_TOKEN;

    uint256 public _rewardsAmount;

    // user => reward
    mapping(address => Reward[]) internal _rewards;

    constructor(address rewardToken, address paymentToken) {
        REWARD_TOKEN = IRewardToken(rewardToken);
        PAYMENT_TOKEN = IERC20(paymentToken);
    }

    function claim(address user) external {
        uint256 length = _rewards[user].length;
        if (length == 0) revert NothingForClaim();

        for (uint256 i = 0; i < length; i++) {
            Reward storage reward = _rewards[user][length - i];

            withdrawLastDeposit(user, reward.amount);
            payRewards(user, reward);
        }

        delete _rewards[user];
    }

    function payRewards(address user, Reward memory reward) internal {
        uint256 random = uint256(keccak256(abi.encodePacked(block.timestamp, SEED)));
        uint256 daysDelta = (block.timestamp - reward.timestamp) / 1 days;
        uint256 userReward = reward.amount / PCT_DENOMINATOR * (random % daysDelta);
        if (userReward > 0) {
            REWARD_TOKEN.rewardUser(user, userReward);
        }
    }

    function withdrawLastDeposit(address user, uint256 amount) internal {
        _rewards[user].pop();

        _rewardsAmount -= amount;
        PAYMENT_TOKEN.transfer(user, amount);
    }

    function depositForRewards(address user, address payer, uint256 amount) internal {
        PAYMENT_TOKEN.transferFrom(payer, address(this), amount);
        _rewardsAmount += amount;

        _rewards[user].push(Reward(block.timestamp, amount));
    }
}


contract Marketplace is Rewardable {
    error AlreadyOwner();
    error NotItemOwner();
    error InvalidSale();
    error AlreadyOnSale();

    struct ItemSale {
        address seller;
        uint256 price;
        uint256 startTime;
    }

    IERC721 internal NFT_TOKEN;

    // nft tokenId => item
    mapping(uint256 => ItemSale) public items;

    constructor(
        address nftToken,
        address paymentToken,
        address rewardToken
    ) Rewardable(rewardToken, paymentToken) {
        NFT_TOKEN = IERC721(nftToken);
    }

    function setForSale(uint256 tokenId, uint256 price, uint256 startTime) external {
        if (NFT_TOKEN.ownerOf(tokenId) != msg.sender) revert NotItemOwner();
        if (block.timestamp > startTime) revert InvalidSale();
        if (items[tokenId].price == price) revert InvalidSale();

        items[tokenId] = ItemSale(msg.sender, price, startTime);
    }

    function discardFromSale(uint256 tokenId) external {
        if (NFT_TOKEN.ownerOf(tokenId) != msg.sender) revert NotItemOwner();

        delete items[tokenId];
    }

    function postponeSale(uint256 tokenId, uint256 postponeSeconds) external {
        if (NFT_TOKEN.ownerOf(tokenId) != msg.sender) revert NotItemOwner();

        ItemSale storage item = items[tokenId]; 
        assembly {
            let s := add(item.slot, 2)
            sstore(s, add(sload(s), postponeSeconds))
        }
    }

    function buy(uint256 tokenId) external {
        address owner = NFT_TOKEN.ownerOf(tokenId);
        if (owner == msg.sender) revert AlreadyOwner();

        if (block.timestamp < items[tokenId].startTime) revert InvalidSale();

        if (items[tokenId].price == 0 ||
            items[tokenId].seller == address(0) ||
            items[tokenId].seller == msg.sender) revert InvalidSale();

        depositForRewards(owner, msg.sender, items[tokenId].price);
        NFT_TOKEN.transferFrom(owner, msg.sender, tokenId);
        delete items[tokenId];
    }
}