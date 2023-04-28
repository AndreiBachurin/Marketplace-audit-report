# MARKETPLACE AUDIT REPORT
Performed by Andrey Bachurin

## Project overview
There is Marketplace contract which allows to buy and sell NFTs exchanging them for payment tokens. 

### Finding Severity breakdown
All vulnerabilities discovered during the audit are classified based on their potential severity and have the following classification:
| Severity | Description |
| ------ | ------ |
| Critical | Bugs leading to assets theft, fund access locking, or any other loss funds to be transferred to any party. |
| High | Bugs that can trigger a contract failure. Further recovery is possible only by manual modification of the contract state or replacement. |
| Medium | Bugs that can break the intended contract logic or expose it to DoS attacks, but do not cause direct loss funds. |
| Low | Bugs that do not have a significant immediate impact and could be easily fixed or bugs that lead to consume extra gas. |

### Project scoupe
Audited project consists of two smart contracts with total of 144 lines. Project description and code of smart contracts are located here:
https://hackmd.io/@idealatom/Sk1YbYH7j

## Findings

### Critical

#### [C-01] Reentrancy possibility through NFT_TOKEN
##### MarketPlace.sol#L141
Сustom `NFT_TOKEN` contract can implement malicious logic: reentrancy in `buy()` function, draining the NFT buyer's assets. 
##### Recomendation
Use OpenZeppelin's ReentrancyGuard or lock modifier in `buy()` function, that prevents `buy()` from being re-entered until all checks have been completed and all effects have been applied:
```Solidity
contract Marketplace is Rewardable {
    ...
    bool private locked;
    
    modifier lock() {
        require(!locked, "Locked");
        locked = true;
        _;
        locked = false;
    }
    ...
    function buy(uint256 tokenId) lock external {
        ...
        depositForRewards(owner, msg.sender, items[tokenId].price);
        NFT_TOKEN.transferFrom(owner, msg.sender, tokenId);
        delete items[tokenId];
    }
```

#### [C-02] Front-running possibility by NFT seller
##### MarketPlace.sol#L130
Ability to change NFT price in `setForSale()` function and lack of checking NFT price at the time of purchase in `buy()` function creates front-running possibility for NFT seller, allowing him to actually sell NFT for more than what was announced.
##### Recomendation
Pass actual NFT price to `buy()` function and compare it with price saved in the `ItemSale` for given `tokenId`:
```Solidity
contract Marketplace is Rewardable {
    ...
    function buy(uint256 tokenId, uint256 actualPrice) external {
        address owner = NFT_TOKEN.ownerOf(tokenId);
        if (owner == msg.sender) revert AlreadyOwner();

        if (block.timestamp < items[tokenId].startTime) revert InvalidSale();

        if (items[tokenId].price == 0 ||
            items[tokenId].price != actualPrice
            items[tokenId].seller == address(0) ||
            items[tokenId].seller == msg.sender) revert InvalidSale();
            ...
```

### High

#### [H-01] Deleting data about rewards before paying them
##### MarketPlace.sol#L50
In `claim()` function, the `withdrawLastDeposit()` function is first called, which removes data about the current rewards:
```Solidity
contract Rewardable {
    ...
    function withdrawLastDeposit(address user, uint256 amount) internal {
        _rewards[user].pop();
        ...
```
Then rewards is sent in the `payRewards()` function, but by this point it will already be zero due to deletion in the previous step.
##### Recomendation
Swap the order of `withdrawLastDeposit()` and `payRewards()` functions calls:
```Solidity
contract Rewardable {
    ...
    function claim(address user) external {
        ...
        for (uint256 i = 0; i < length; i++) {
            Reward storage reward = _rewards[user][length - i];
            
            payRewards(user, reward);
            withdrawLastDeposit(user, reward.amount);
        ...
```

#### [H-02] Rounding error possibility in rewards calculating
##### MarketPlace.sol#L59
Rewards may be calculated incorrect due to rounding because of wrong order of arithmetic operations. 
##### Recomendation
Swap the order of arithmetic operations as follows:
```Solidity
contract Rewardable {
    ...
    function payRewards(address user, Reward memory reward) internal {
        ...
        uint256 userReward = reward.amount * (random % daysDelta) / PCT_DENOMINATOR;
        ...
```

#### [H-03] Error probability: division by zero
##### MarketPlace.sol#L59
If less than 1 day has passed since the purchase of NFT, `daysDelta` will be equal to zero, and it will be error on the next line: modulo divizion by zero.
##### Recomendation
Add check for `daysDelta`, and if it equal to zero, set to 1:
```Solidity
contract Rewardable {
    ...
    function payRewards(address user, Reward memory reward) internal {
        ...
        uint256 daysDelta = (block.timestamp - reward.timestamp) / 1 days;
        if (daysDelta == 0) {
            daysDelta = 1;
        }
        uint256 userReward = reward.amount / PCT_DENOMINATOR * (random % daysDelta);
        ...
```

#### [H-04] Overflow probability in assembly
##### MarketPlace.sol#L126
In assembly block, `startTime` and `postponeSeconds` are added, which can cause an overflow, because assembly does not have automatic prevention against overflow and underflow.
##### Recomendation
Replace assembly code with solidity:
```Solidity
contract Rewardable {
    ...
    function postponeSale(uint256 tokenId, uint256 postponeSeconds) external {
        if (NFT_TOKEN.ownerOf(tokenId) != msg.sender) revert NotItemOwner();

        items[tokenId].price += postponeSeconds;
    }    
```

#### [H-05] Incorrect indexing of array elements
##### MarketPlace.sol#L47
When iterating array in loop, last element of array is read, but it is stored with idnex [length - 1], not [length]. It will throw out of bounds error.
##### Recomendation
Change array indexing as follows:
```Solidity
contract Rewardable {
    ...
    function claim(address user) external {
        uint256 length = _rewards[user].length;
        if (length == 0) revert NothingForClaim();

        for (uint256 i = 0; i < length; i++) {
            Reward storage reward = _rewards[user][length - i - 1];
            ...   
```

#### [H-06] Insecure randomness generation
##### MarketPlace.sol#L57
Random is generated from `SEED` and `block.timestamp` parameters. But value of `SEED` can be known, despite the fact that it is private state variable, because constants are stored in contract's bytecode. Also, miner can manipulate `block.timestamp` value and user can brut force different values of `block.timestamp` for claim more rewards.
```Solidity
contract Rewardable {
    ...
    function payRewards(address user, Reward memory reward) internal {
        uint256 random = uint256(keccak256(abi.encodePacked(block.timestamp, SEED)));
        ...
```
##### Recomendation
* Store `SEED` value off-chain or encrypted;
* Use external sources of randomness, such as Chainlink VRF oracle.

### Medium

#### [M-01] DoS possibility due to error on external call of PAYMENT_TOKEN contract
##### MarketPlace.sol#L69
External call to the `PAYMENT_TOKEN` contract may fail. Given that this call implement in  loop, it can lead to stop in the payment of all deposits and rewards of users.
##### Recomendation
Add check for the result returned by the contract and handle possible call errors:
```Solidity
contract Rewardable {
    ...
    function withdrawLastDeposit(address user, uint256 amount) internal {
        ...
        (bool sucess, bytes memory data) = address(PAYMENT_TOKEN).call(abi.encodeWithSignature("transfer(address,amount)", user, amount));
        if (!sucess) {
            //error handler logic
        }
        ...
```
or use SafeERC20 library ([M-05]).

#### [M-02] DoS possibility due to error on external call of REWARD_TOKEN contract
##### MarketPlace.sol#L61
External call to the `REWARD_TOKEN` contract may fail. Given that this call implement in  loop, it can lead to stop in the payment of all deposits and rewards of users.
##### Recomendation
Add check for the result returned by the contract and handle possible call errors:
```Solidity
contract Rewardable {
    ...
    function payRewards(address user, Reward memory reward) internal {
        ...
        if (userReward > 0) {
            (bool sucess, bytes memory data) = address(REWARD_TOKEN).call(abi.encodeWithSignature("rewardUser(address,amount)", user, userReward));
                if (!sucess) {
                    //error handler logic
                }
        ...
```
or use SafeERC20 library ([M-05]).

#### [M-03] DoS possibility due to reaching gas limit while loop iterating
##### MarketPlace.sol#L46
Loop in `claim()` function implements expensive gas calls to external contracts. Given that the loop is not limited (if user have very many deposits), it can lead to reach gas limit so contract will stop and funds will lost.
##### Recomendation
Limit maximum number of user's deposits.

#### [M-04] Anyone can claim rewards for user
##### MarketPlace.sol#L42
Anyone can call `claim()` function and withdraw funds and claim reward to other user. Given that amount of rewards depends on the number of days passed from sale NFT, `user` may lose part of rewards.
##### Recomendation
Add check that user equal msg.sender:
```Solidity
contract Rewardable {
    ...
    function claim(address user) external {
        requre(user == msg.sender, "You have no permission to do this");
        ...
```
or just change `user` to `msg.sender` in `claim()` function.

#### [M-05] Unsafe version of  ERC20 transfer/transferFrom
##### MarketPlace.sol#L69,73
`Claim()` and `buy()` functions call `transfer()` and `transferFrom()` functions on `PAYMENT_TOKEN` contract, but return values are not checked, that can lead to unexpected call resalts. In addition, Marketplace cannot use some ERC20 tokens that do not return bool when call it transfer/transferFrom (like USDT), as `PAYMENT_TOKEN`.
##### Recomendation
Use OpenZeppelin's SafeERC20 library.

#### [M-06] Old pragma version
##### MarketPlace.sol#L3
Contracts allow pragma 0.8.0 and higher, however custom errors used in contact `Rewardable` only appeared in version 0.8.4 of solidity. In addition, older versions of solidity may contain known bugs that degrade contracts security.
##### Recomendation
Use new version of pragma.

#### [M-07] Pragma version is not locked
##### MarketPlace.sol#L3
Prod version of Marketplace should be deployed with the same compiler version it was tested with. Locking the pragma version ensures that the contract will not be deployed with the latest unstable or insecure compiler version.
##### Recomendation
Lock pragma version.

### Low

#### [L-01] Unnecessary check in buy() function
##### MarketPlace.sol#L138
There is check in the `buy()` function:
```Solidity
if (items[tokenId].price == 0 ||
    items[tokenId].seller == address(0) ||
    items[tokenId].seller == msg.sender) revert InvalidSale();
```
However, there is a check on line 133:
```Solidity
address owner = NFT_TOKEN.ownerOf(tokenId);
if (owner == msg.sender) revert AlreadyOwner();
```
Given that owner = NFT_TOKEN.ownerOf(tokenId), and in the `setForSale()` function, value `NFT_TOKEN.ownerOf(tokenId)` is stored in `items[tokenId].seller`. So the check on line 139 is unnecessary and consumes extra gas.
##### Recomendation
Remove check on line 139

#### [L-02] Repeated check in different functions
##### MarketPlace.sol#L107,115,121
`setForSale()`, `discardFromSale()` and `postponeSale()` functions have check NFT_TOKEN.ownerOf(tokenId) != msg.sender.
##### Recomendation
Change this checks by modifier to improve code readability.

#### [L-03] No check postpone for zero seconds
##### MarketPlace.sol#L120
NFT sale can be postponed by zero seconds, but it makes no sense.
##### Recomendation
Add postponeSeconds check:
```Solidity
contract Marketplace {
    ...
    function postponeSale(uint256 tokenId, uint256 postponeSeconds) external {
        require(postponeSeconds != 0, "Wrong postpone");
        ...
```

#### [L-04] Unused SafeMath library
##### MarketPlace.sol#L8,17
There is SafeMath library in the Marketplace, but it is not needed, since the Solidity version is ^0.8.0.
##### Recomendation
Remove library import and line 17.

#### [L-05] Unused IERC20Metadata interface
##### MarketPlace.sol#L6
Line 6 imports `IERC20Metadata.sol`, but it is not used in the Marketplace.
##### Recomendation
Remove import on line 6.

#### [L-06] Multiple call to state variable
##### MarketPlace.sol#L134,136,137,138
`buy()` function performs several checks, each of which calls `items[tokenId]` from storage. It consumes a lot of gas because reading from storage is more expensive than reading from memory.
##### Recomendation
Cache `items[tokenId]` in memory before checks:
```Solidity
contract Marketplace {
    ...
    function buy(uint256 tokenId) external {
        ...
        ItemSale memory item = items[tokenId];
        if (block.timestamp < item.startTime) revert InvalidSale();

        if (item.price == 0 ||
            item.seller == address(0) ||
            item.seller == msg.sender) revert InvalidSale();
        ...
```

## Conclusion

A total of 21 vulnerabilities broken down by severity levels:
| Severity | Amount |
| ------ | ------ |
| Critical | 2 |
| High | 6 |
| Medium | 7 |
| Low | 6 |
