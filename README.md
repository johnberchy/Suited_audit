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

``function checkpoint(uint256 seq, address[] calldata players_, int256[] calldata deltas, uint256 rake)
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
  }``

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
Reentrancy: every token-moving function is nonReentrant and updates state before _payOut. claimRakeback, requestExit, and cancelExit make no external calls. rescueToken is unguarded but owner-only.
Accounting drift: every path preserves Σ balances == liabilities and conserves liabilities + rakeCollected (or reduces it by exactly the token amount paid out). liabilities -= rake cannot underflow.
Deposit inflation: crediting the measured balance delta defeats fee-on-transfer tokens. Donations only add slack.
Arithmetic edge cases: int256.min negation and sum overflow panic rather than wrap. SafeCast bounds rake.
Permit front-running: the try/catch plus the transferFrom gate is correct. A phantom-permit token like WETH9 would matter only if the money token had a permissive fallback.
Duplicates and non-depositors in checkpoints: the O(n²) check is bounded at 24, and everDeposited blocks typo'd addresses.
Priorities
Bound what the settler key can do per player (F1). This is the only finding with total-loss impact.
Close the exit/auth exposure race with gateway locks plus a configurable exitDelay and an auth TTL cap (F2).
Add the solvency post-condition to rescueToken (F3).

I can write Foundry PoC tests for F1 and F2 if you want to confirm them against your gateway assumptions.

ok write for me a Foundry PoC tests for F1 and F2 i hve confirmed them against my gateway assumptions.

I haven't compiled or run this file, so expect to fix a typo or two on the first forge test.

Setup

Put the contract at src/Suited.sol and the test at test/SuitedPoC.t.sol.
Install the dependencies: forge install foundry-rs/forge-std openzeppelin/openzeppelin-contracts.
Add this remapping: @openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/.
If OZ complains about opcodes, set evm_version = "cancun" in foundry.toml.
Run it with forge test --match-contract SuitedPoC -vv.

What each test proves

Test	Demonstrates
test_F1_settlerDrainsVictimsIntoAttackerWallet	One valid 24-entry checkpoint moves 23 victims' balances to the attacker. The attacker withdraws after the owner pauses, and the solvency assert never trips.
test_F1_victimExitHatchIsClampedAwayByCheckpoint	A victim's pending exit is clamped to 0 by the same checkpoint, so claimExit reverts with InvalidAmount.
test_F1_ownerKeyEscalatesToSettlerInstantly	setSettler has no timelock, so a compromised owner key becomes a drain immediately.
test_F2A_exitClaimedAfterOffchainLossWedgesBatch	The attacker exits after losing off-chain, the checkpoint reverts, and an unrelated c/d pair in the same batch is blocked with it. The gateway must rebuild the batch.
test_F2B_preSignedWithdrawAuthSpentAfterOffchainLoss	A full-bankroll auth is still spendable 9 minutes in, after the chips were lost.
test_F2C_pauseFreezesSettlementButNotExitClocks	Pause blocks the checkpoint but not claimExit, and the hand can never be settled afterward.

Reading the results

Each test asserts the current vulnerable behavior, so they all pass today. After you fix a finding, the matching test should fail, which makes it a regression signal. Invert or rewrite it then.
test_F1_settlerDrainsVictimsIntoAttackerWallet is the one to extend for a fix: after adding a player-signed stake cap or per-checkpoint debit limit, assert that the checkpoint now reverts.
For F2, exitDelay is fixed at construction, so testing a longer delay means redeploying with a different constructor value, not calling a setter.

If you want, I can add fix-verification tests for whichever mitigation you pick.

Suitedpoc.t
SOL 

A VPS (Virtual Private Server) is a slice of a physical server that's been split up — using virtualization software — into several independent virtual machines, each acting like its own dedicated computer. You rent one of those slices, get your own operating system, root/admin access, and a fixed share of CPU, RAM, and storage, isolated from the other VPSs on the same physical hardware even though you're all sharing it underneath.

Where it sits relative to other hosting options
Shared hosting — you share an OS and resources with many other accounts, no root access, cheapest, least control, least isolation.
VPS — you get your own OS instance and root access, resources are reserved (not fought over), but still physically sharing a machine with others. Mid-price, mid-control.
Dedicated server — an entire physical machine is yours alone. Most expensive, most control, best performance ceiling.
Cloud instances (AWS EC2, DigitalOcean Droplets, etc.) — conceptually the same thing as a VPS, just offered with more elastic, pay-by-the-hour scaling and a bigger ecosystem of managed services around it. Most "cloud servers" you rent today are technically VPSs under a different marketing name.
What people actually use one for
Hosting a website, API, or app that needs more control/performance than shared hosting allows
Running a backend/database for something you built
Self-hosting services (game servers, VPNs, bots, personal cloud storage)
A persistent machine for long-running scripts, dev environments, or — relevant to this conversation — running a blockchain node, keeper bot, or gateway server that needs to be always-on
Why it's relevant to what you've been working on

If you're running something like the off-chain gateway or settler bot for the Suited contract we reviewed, a VPS is exactly the kind of place that process would live — which also means it becomes part of your key-custody picture: wherever the settler private key gets loaded into memory to sign checkpoints, that VPS's security (SSH access, who has root, whether secrets are in plaintext env vars vs a vault/HSM) is now directly tied to the F1 risk we discussed. A compromised VPS running an unprotected settler key is one of the most realistic versions of the "attacker gets the key" step.

If that's the direction you're heading, I'm glad to go through what reasonable key-custody hygiene looks like on a VPS (not storing raw keys in env files, using a signing service or HSM, restricting SSH, etc.).

Critical: the standing max allowance to staking bypasses every guard in the contract. does this bug still exists after deployment

Yes — this one is still live on the deployed contract, and unlike Finding 2 (which is mostly a gateway/off-chain fix), there's no admin call that turns this one off.

Why it can't be patched with an existing function

The unlimited allowance is set in two places, both baked into the deployed bytecode:

solidity
// constructor
token.forceApprove(address(legs.staking), type(uint256).max);
solidity
// setStaking
function setStaking(IStakingRewards staking_) external onlyAdmin {
    ...
    (bool ok,) = address(token).call(abi.encodeCall(IERC20.approve, (address(staking), 0)));
    ok; // ignored
    staking = staking_;
    token.forceApprove(address(staking_), type(uint256).max);   // ← same unbounded grant, every time
    emit StakingChanged(address(staking_));
}

There is no standalone "revoke allowance" or "set allowance to 0 while keeping the same staking contract" function. The only lever that touches this allowance is setStaking, and every single path through it re-grants type(uint256).max to whatever address you pass — including if you tried calling setStaking with the same staking address, you'd still end up back at max allowance. There's no way to run this contract at all (i.e., have notifyRewardAmount ever work) without staking holding an unlimited, standing allowance.

So the vulnerable condition — whoever controls the staking contract can call transferFrom on the splitter at any time, for any amount, completely outside split/distribute — exists continuously, for as long as this contract is deployed, as a structural property of its design. It was true the moment the constructor ran, and it'll be true tomorrow.

What setStaking can do (and can't)

Rotating to a different staking contract doesn't close the hole — it just moves it. The new contract gets the same unlimited allowance. The only thing that changes is whose trustworthiness the exposure now depends on. You could reduce real-world risk by:

Confirming staking is a battle-tested, audited, non-upgradeable contract whose only external-facing functions are the ones it needs (no sweep/rescue/emergency-withdraw function sitting on top of the same allowance).
Checking right now, with cast call <splitter> "staking()(address)", exactly what's set, and auditing that contract's full function list for anything capable of moving tokens out on its own authority.

But none of that eliminates the bug — it just bets on the current staking contract never having (or never being given) a function like the ownerPullFrom I used in the PoC. That's a much weaker guarantee than "the splitter structurally can't lose more than the stakers' share," which is what the contract's own header comment claims.

The actual fix requires a new contract

To genuinely close this, you'd need a splitter whose notifyRewardAmount call is preceded by a just-in-time approval — approve exactly toStakers, call, then reset to 0 — instead of a standing max allowance. That's a code change to _distribute() and the constructor, which means:

Deploy a patched CreatorFeeSplitterV2.
Point the collection wallet's allowance (and whatever upstream process calls split) at the new contract.
Decommission the old one — ideally by also revoking the collector's allowance to it, since an old, abandoned splitter still sitting with a live allowance from the collector wallet is its own lingering risk.
Bottom line
Question	Answer
Does the bug exist on your live deployment right now?	Yes
Can an admin call fix it?	No — every path re-grants unlimited allowance
Can setStaking mitigate it?	Only by choosing a trustworthy destination, not by removing the structural flaw
Does fixing it require a redeploy?	Yes

If it'd help, I can check what staking currently points to has the same ownerPullFrom-shaped risk — paste or point me to that contract's source and I'll tell you how exposed you actually are today, versus how exposed the design is in the abstract.
