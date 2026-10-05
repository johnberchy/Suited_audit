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

# Issues Found: Three findings in suited.sol vault contract

# ISSUE MEDIUM:1 (TRUST MODEL): HOTKEY WHEN COMPROMISED CAN MOVE EVERY PLAYERS BALANCE, AND THE EXIT HATCH DOESN'T STOP IT #L321

Code snippet - src/contract/Suited.sol

# Summary

The header/comment says the settler "can move only in zero-sum steps." That holds for the vault as a whole but not for individual players. Zero-sum means no mint, not no theft.

# Vulnerability details

The solvency assert is global and transfers between players leave it unchanged.

```solidity
if (token.balanceOf(address(this)) < liabilities + rakeCollected) revert VaultUndercollateralised();
```

Pause only stops later checkpoints. It doesn't stop when a malicious actor's foothold wallet with the compromised server hotkeys who disguises as a player calls ``deposit(minDeposit)`` so ``everDeposited = true``

```solidity
Player storage p = players[players_[i]];
if (!p.everDeposited) revert NotAPlayer();
```

The malicious actor(W) calls ``checkpoint``(seq+1, [V1…V23, W], [−bal(V1)…−bal(V23), +Σ], 0)(using 23 victims/players as a scenario)

Every guard passes: caller is the settler, seq is correct, the deltas sum to 0, there are no duplicates, all wallets have deposited, and each debit is ≤ that victim's balance. Per-player deltas have no cap, and ``maxRakePerCheckpoint`` only bounds rake.

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

A victim who already called ``requestExit`` has ``exitAmount clamped down by the same checkpoint ``(if (p.exitAmount > p.balance)``. The exit hatch protects against a settler that refuses to sign, not one that is malicious.


# Impact:

Total, instantaneous loss of every player's on-chain balance,

# ISSUE MEDIUM-2: EXITS AND PRE-SIGNED AUTHS ARE CLAIMS ON THE SAME BALANCE THAT OFFCHAIN HANDS STAKE #L447,L349,L428,L481,

Code Snippet - src/contract/Suited.sol

# Summary:
The owner calls ``setPaused(true)`` mid-incident, checkpoint is blocked (can't reconcile any hand), but ``requestExit``, ``claimExit``, and ``withdraw`` all keep working exactly as before — which is precisely what lets a pending exit clock, started before the pause, finish and pay out during the pause window, against a hand that will now never be checkpointed at all. These does not require any setSettler or the hotkeys been compromized,any player can run this

# Vulnerability Details:

```solidity
function claimExit() external nonReentrant {
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
}
```

``claimExit``checks only the caller's balance, the time, and the signature, here are his checks:

```solidity
p.exitAt == 0   //is there a pending exit at all

block.timestamp < p.exitAt   //has the delay elapsed

amount == 0   //amount > 0 after clamping

the clamp itself, p.exitAmount > p.balance ? p.balance : p.exitAmount  //caps against whatever p.balance currently is on-chain
```

Here are three sequence a malicious actor can play;

1st sequence 

< Malicious Actor(A) deposits 1000 and calls requestExit(1000).

< If the gateway still seats them, A loses 1000 to B who is the oppenent off-chain just before exitAt.

< he calls claimExit() and is paid 1000.

< The gateway's checkpoint [A:-1000, B: +1000] reverts with InsufficientBalance

Why it reverts: by the time this checkpoint is submitted, A's on-chain balance has already been reduced to 0 by ``claimExit()``. So when checkpoint tries to apply -1000 to A:

```
uint256 debit = uint256(-delta);
if (p.balance < debit) revert InsufficientBalance();
```

``p.balance (0)`` is less than ``debit (1000)``, so it reverts — and because the whole checkpoint call is one transaction, B's +1000 credit never lands either, even though B was the rightful winner.

```solidity
function requestExit(uint256 amount) external {
    if (amount == 0) revert InvalidAmount();
    Player storage p = players[msg.sender];
    if (amount > p.balance) revert InsufficientBalance();
    p.exitAmount = amount;
    p.exitAt = uint64(block.timestamp + exitDelay);
    emit ExitRequested(msg.sender, amount, p.exitAt);
}
```
2nd sequence

< The gateway issues a withdraw auth for the full bankroll with a deadline minutes away.

< The actor holds the signature, sits down with full chips, and loses.

< They submit withdraw before the deadline and are paid.

< The checkpoint reverts the same way.

```solidity
function _consumeAuth(bytes32 typehash, uint256 amount, bytes32 authId, uint256 deadline, bytes calldata sig)
    internal
{
    if (block.timestamp > deadline) revert AuthExpired();
    if (usedAuths[authId]) revert AuthUsed();
    bytes32 digest =
        _hashTypedDataV4(keccak256(abi.encode(typehash, msg.sender, amount, authId, deadline)));
    if (ECDSA.recover(digest, sig) != settler) revert BadAuthSignature();
    usedAuths[authId] = true;
}
```

 3rd Sequence (pause): The pause asymmetry that lets this all happen mid-incident
 
 ```solidity
modifier whenNotPaused() {
    if (paused) revert EnforcedPause();
    _;
}
```

 < Owner pauses during an incident.
 
 < Checkpoints stop but exit clocks keep running,
 
 < Pending exits become claimable against hands that were never settled.

``claimExit`` and ``_consumeAuth`` check only the caller's balance, the time, and the signature. Nothing on-chain knows chips are in play. The exit clamp runs only inside checkpoint, which is too late.

# Impact:

The vault stays solvent. The loss falls on counterparties or the house through off-chain obligations that can't be collected.
The whole 24-entry batch reverts. Because ``checkpointSeq`` is global, one wedged batch stalls every table until the gateway rebuilds it.

# Recommendation

< Gateway: treat ``ExitRequested`` as hard seat removal and require ``exitDelay`` ≥ worst-case hand + checkpoint latency + retries.

< Gateway: treat an issued auth as locked funds until it is consumed (usedAuths) or expired.

< Contract: cap auth TTL (e.g. deadline <= block.timestamp + 10 minutes).

< Contract: add an owner setter for exitDelay within MAX_EXIT_DELAY. Right now it is fixed at construction, though the comment calls it configurable.



# ISSUE LOW:3 RESCUE TOKEN CHECKS ADDRESS IDENTITY, NOT ASSET IDENTITY #L271

Code Snippet - src/contract/Suited.sol

# Summary

If the money token ever has an alias entry point (dual-address or proxy-facade tokens), the owner can call setRakeDestination(self) and then rescueToken(alias, amount), bypassing the stray == token check and draining player funds. It is unlikely for USDG, but the fix is cheap: after the transfer, assert token.balanceOf(this) >= liabilities + rakeCollected. Also:

rakeDestination can be set to address(this), which makes withdrawRake a self-transfer that permanently strands collateral.
The "owner chooses when, never where" comment overclaims, since ``setRakeDestination`` is instant.

# Vulnerability Details

```solidity
function rescueToken(IERC20 stray, uint256 amount) external onlyOwner {
    if (address(stray) == address(token)) revert InvalidDestination();
    stray.safeTransfer(rakeDestination, amount);
}
```

The function's only safety check is address equality: ``stray != token``. That's checking which address is pass in, not what asset that address actually represents. These are the same thing only under an assumption the contract never verifies: that every ERC-20-shaped contract has exactly one canonical address.

```solidity
setRakeDestination(ownerControlledAddress);   // onlyOwner, takes effect immediately
rescueToken(aliasAddressForUSDG, amount);     // passes the stray != token check
```

This can occur when the owner ``rescueToken`` happily calls ``stray.safeTransfer(rakeDestination, amount)``, and because stray is an alias for the real money token, this moves actual player-backing collateral out of the vault — collateral the header comment explicitly calls "deliberately unsweepable."

# Impact:

Direct loss: Real USDG backing player balances leaves the vault, through a function whose entire design promise is that it can't do that. This requires the owner key and the condition that USDG (or a facade pointing at it) has more than one valid address — it isn't exploitable by an outside malicious actor with no privileged access, and it isn't exploitable at all if USDG only ever has one canonical address.


