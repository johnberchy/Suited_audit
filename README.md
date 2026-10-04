# SUITED INDEPENDENT AND VOLUNTRY AUDITING

# Findings
Each issue has an assigned severity:
• High issues are directly exploitable security vulnerabilities that need to be fixed.

• Medium issues are security vulnerabilities that may not be directly exploitable or
may require certain conditions in order to be exploited. All major issues should be
addressed.

• Low/Info issues are non-exploitable, informational findings that do not pose a
security risk or impact the system’s integrity. These issues are typically cosmetic or
related to compliance requirements, and are not considered a priority for
remediation.

# Issues Found: 4 findings in suited.sol vault contract

# ISSUE M:1 (trust model): HOTKEY WHEN COMPROMISED CAN MOVE EVERY PLAYERS BALANCE, AND THE EXIT HATCH DOESN'T STOP IT

# Summary

The header/Ccomment says the settler "can move only in zero-sum steps." That holds for the vault as a whole but not for individual players. Zero-sum means no mint, not no theft.

# Vulnerability details

The solvency assert is global and transfers between players leave it unchanged.

``if (token.balanceOf(address(this)) < liabilities + rakeCollected) revert VaultUndercollateralised();``

Pause only stops later checkpoints. It doesn't stop when an attacker's foothold wallet with the compromised server hotkeys who disguises as a player calls deposit(minDeposit) so everDeposited = true

`` Player storage p = players[players_[i]];
if (!p.everDeposited) revert NotAPlayer();``

The malicious actor calls checkpoint(seq+1, [V1…V23, W], [−bal(V1)…−bal(V23), +Σ], 0)(using 24 victims/players as a scenario) Every guard passes: caller is the settler, seq is correct, the deltas sum to 0, there are no duplicates, all wallets have deposited, and each debit is ≤ that victim's balance. Per-player deltas have no cap, and maxRakePerCheckpoint only bounds rake.

```solidity
function checkpoint(uint256 seq, address[] calldata players_, int256[] calldata deltas, uint256 rake)
    external
    onlySettler       
    whenNotPaused       
    nonReentrant
{
    uint256 n = deltas.length;
    if (n == 0 || n > MAX_CHECKPOINT_ENTRIES) revert TooManyEntries();      
    if (players_.length != n) revert AccountCountMismatch();               
    if (seq != checkpointSeq + 1) revert CheckpointOutOfOrder();           

    int256 sum = 0;
    for (uint256 i = 0; i < n; i++) { sum += deltas[i]; }
    if (sum + rake.toInt256() != 0) revert CheckpointNotZeroSum();         
    if (rake > maxRakePerCheckpoint) revert RakeTooLarge();                

    for (uint256 i = 0; i < n; i++) {
        for (uint256 j = 0; j < i; j++) {
            if (players_[j] == players_[i]) revert DuplicatePlayer();      
        }
        Player storage p = players[players_[i]];
        if (!p.everDeposited) revert NotAPlayer();                        
        int256 delta = deltas[i];
        if (delta >= 0) {
            p.balance += uint256(delta);
        } else {
            uint256 debit = uint256(-delta);
            if (p.balance < debit) revert InsufficientBalance();           
            p.balance -= debit;
        }
    }
  }
```

The malicious actor reads each victim's actual on-chain balance via the public players mapping before building the batch, and debits exactly that amount, never more.

A victim who already called requestExit has exitAmount clamped down by the same checkpoint (if (p.exitAmount > p.balance)). The exit hatch protects against a settler that refuses to sign, not one that is malicious.


# IMPACT



# ISSUE M:2 —  exits and pre-signed auths are claims on the same balance that off-chain hands stake

# Summary:

# Vulnerability Details:

```function claimExit() external nonReentrant {
    Player storage p = players[msg.sender];
    if (p.exitAt == 0) revert NoPendingExit();
    if (block.timestamp < p.exitAt) revert ExitNotReady();
    uint256 amount = p.exitAmount > p.balance ? p.balance : p.exitAmount;
    if (amount == 0) revert InvalidAmount();
    p.balance -= amount;
    p.exitAmount = 0;
    p.exitAt = 0;
    liabilities -= amount;
    _payOut(msg.sender, amount);
    emit Withdrawn(msg.sender, amount, p.balance, true);
}```

claimExit ... check[s] only the caller's balance, the time, and the signature, here are his four checks:

p.exitAt == 0 //is there a pending exit at all
block.timestamp < p.exitAt  //has the delay elapsed
amount == 0  //non-zero after clamping
the clamp itself, p.exitAmount > p.balance ? p.balance : p.exitAmount  //caps against whatever p.balance currently is on-chain

here are three sequence a malicious actor;
1st sequence can be

< Actor deposits 200 and calls requestExit(200).
< If the gateway still seats them, they lose 200 to B off-chain just before exitAt.
< They call claimExit() and are paid 200.
< The gateway's checkpoint [A:-200, B: +200] reverts with InsufficientBalance

```function requestExit(uint256 amount) external {
    if (amount == 0) revert InvalidAmount();
    Player storage p = players[msg.sender];
    if (amount > p.balance) revert InsufficientBalance();
    p.exitAmount = amount;
    p.exitAt = uint64(block.timestamp + exitDelay);
    emit ExitRequested(msg.sender, amount, p.exitAt);
}```



Sequence C (pause): the owner pauses during an incident. Checkpoints stop but exit clocks keep running, so pending exits become claimable against hands that were never settled.

claimExit and _consumeAuth check only the caller's balance, the time, and the signature. Nothing on-chain knows chips are in play. The exit clamp runs only inside checkpoint, which is too late.

# Impact:

The vault stays solvent. The loss falls on counterparties or the house through off-chain obligations that can't be collected.
The whole 24-entry batch reverts. Because checkpointSeq is global, one wedged batch stalls every table until the gateway rebuilds it.

Fixes:

Gateway: treat ExitRequested as hard seat removal and require exitDelay ≥ worst-case hand + checkpoint latency + retries.
Gateway: treat an issued auth as locked funds until it is consumed (usedAuths) or expired.
Contract: cap auth TTL (e.g. deadline <= block.timestamp + 10 minutes).
Contract: add an owner setter for exitDelay within MAX_EXIT_DELAY. Right now it is fixed at construction, though the comment calls it configurable.



F3 — Low: rescueToken checks address identity, not asset identity

If the money token ever has an alias entry point (dual-address or proxy-facade tokens), the owner can call setRakeDestination(self) and then rescueToken(alias, amount), bypassing the stray == token check and draining player funds. It is unlikely for USDG, but the fix is cheap: after the transfer, assert token.balanceOf(this) >= liabilities + rakeCollected. Also:

rakeDestination can be set to address(this), which makes withdrawRake a self-transfer that permanently strands collateral.
The "owner chooses when, never where" comment overclaims, since setRakeDestination is instant.
F4 — Low / informational
_consumeAuth uses ECDSA.recover, so the settler must be an EOA. Rotating to a multisig silently kills withdraw and redeemRakeback.
A shortfall (token seizure or negative rebase) makes every checkpoint revert VaultUndercollateralised, because liabilities only fall through exits. Exits then run first come, first served. This matches your stated design, but it is a stall.
claimExit reverts with InvalidAmount when the clamped amount is 0 but leaves exitAt set. The player must call cancelExit.
claimRakeback and redeemRakeback cap each call but not the cumulative total.
Leads I tried and ruled out
Signature replay: the digest binds the typehash, msg.sender, amount, authId, and deadline, and the domain binds chainId and contract address.
WithdrawAuth and RedeemAuth have different typehashes, and usedAuths is one shared namespace.
A front-runner's call fails signature recovery and rolls back, so it can't burn the authId.
OZ ECDSA rejects malleable signatures, and consumption is by authId, not signature hash.
Reentrancy: every token-moving function is nonReentrant and updates state before _payOut. claimRakeback, requestExit, and cancelExit make no external calls. re


