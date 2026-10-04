// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {Ownable2Step, Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

///                      48
///                      48
///                      48
///                     4488
///                    444888
///                 44444 88888
///                444444 888888
///              44444444 88888888
///             444444444 888888888
///           44444444444 88888888888
///         4444444444444 8888888888888
///       444444444444444 888888888888888
///     44444444444444444 88888888888888888
///  44444444444444444444 8888888888888888888
/// 4444444444444444444444 88888888888888888888
///  44444444444444444444 8888888888888888888
///     44444444444444444 88888888888888888
///       444444444444444 888888888888888
///         4444444444444 8888888888888
///           44444444444 88888888888
///             444444444 888888888
///              44444444 88888888
///                444444 888888
///                 44444 88888
///                    444888
///                     4488
///                      48
///                      48
////                     48
/// Suited — USDG custody and hand settlement on Robinhood Chain.
///
/// A faithful port of the Solana program (programs/suited/src/lib.rs). The
/// game runs off-chain; the chain is three things and nothing more:
///
///   1. a vault — the contract's own token balance backs every liability;
///   2. a per-wallet balance sheet the game server (the "settler") can move
///      only in zero-sum steps, never mint from;
///   3. an exit the server cannot block — request/claim need only the
///      player's own key and survive pause.
///
/// One bankroll per wallet, not one vault per table. Hands, seats, and
/// tournaments live in the gateway; the chain sees netted checkpoints.
///
/// What changed in translation from Solana, deliberately:
///
///   - The dual-signature withdraw/redeem transactions become EIP-712
///     authorizations: the settler signs a typed struct naming the player,
///     amount, a one-time authId, and a short deadline; the player submits
///     it and is paid as msg.sender. Consumed authIds make crash recovery a
///     direct read (`usedAuths`) instead of timestamp reasoning, and
///     msg.sender-as-recipient closes the server-built-transaction
///     redirection class entirely.
///   - `propose_authority`/`accept_authority` is Ownable2Step verbatim.
///   - Checkpoint entries must name wallets that have deposited at least
///     once (`everDeposited`) — the same account-must-exist rule the Solana
///     runtime enforced implicitly, and the reason a typo'd address reverts
///     the batch instead of stranding money in it.
///   - Deposits credit the measured balance delta, so a nonstandard token
///     can never push `liabilities` past the vault and wedge settlement.
///
/// Everything else — guard order, caps, clamps, the pause asymmetry, the
/// solvency assert after every checkpoint — mirrors lib.rs one for one.
contract Suited is Ownable2Step, ReentrancyGuard, EIP712 {
    using SafeERC20 for IERC20;
    using SafeCast for uint256;

    // ── constants ─────────────────────────────────────────────────────────

    /// Cap on players per checkpoint. On Solana this was a compute-budget
    /// bound; here the bound is gas and 24 is nowhere near it — but the
    /// gateway's batching logic is built around this number, so it stays
    /// until raising it is a deliberate, tested decision.
    uint256 public constant MAX_CHECKPOINT_ENTRIES = 24;

    /// Cap on the configurable exit delay, so a malicious admin cannot trap
    /// funds behind an arbitrarily long wait.
    uint256 public constant MAX_EXIT_DELAY = 7 days;

    bytes32 public constant WITHDRAW_AUTH_TYPEHASH =
        keccak256("WithdrawAuth(address player,uint256 amount,bytes32 authId,uint256 deadline)");
    bytes32 public constant REDEEM_AUTH_TYPEHASH =
        keccak256("RedeemAuth(address player,uint256 amount,bytes32 authId,uint256 deadline)");

    // ── state ─────────────────────────────────────────────────────────────

    /// The money. USDG on mainnet, MockUSDG on testnet. Fixed for life —
    /// switching tokens is a redeploy, exactly as switching mints was.
    IERC20 public immutable token;

    /// The game server's hot key. Signs checkpoints and withdraw/redeem
    /// authorizations. Rotatable by the owner without touching custody.
    address public settler;

    /// The only address rake may be swept to. The owner chooses when,
    /// never where.
    address public rakeDestination;

    /// Per-call ceiling on rake booked by a checkpoint and on any single
    /// rakeback movement — one compromised call cannot drain the pool.
    uint256 public maxRakePerCheckpoint;

    uint256 public minDeposit;

    /// Σ of all player balances. The solvency invariant is
    /// `token.balanceOf(this) >= liabilities + rakeCollected`, asserted
    /// after every checkpoint. Outbound transfers check only that the vault
    /// covers the amount — deliberately weaker, so that under a shortfall
    /// players can still take what remains instead of being trapped behind
    /// a full-solvency precondition.
    uint256 public liabilities;

    /// Rake taken out of checkpoints and not yet swept or returned as
    /// rakeback.
    uint256 public rakeCollected;

    /// Strictly increasing; a checkpoint must carry exactly seq+1. The
    /// gateway's crash recovery relies on this being the only path forward.
    uint256 public checkpointSeq;

    /// Seconds between requestExit and claimExit.
    uint256 public exitDelay;

    /// Pause halts deposit, checkpoint, and both rakeback paths. It NEVER
    /// halts withdraw, the exit hatch, or the rake sweep — an operator
    /// incident must not be able to trap player money.
    bool public paused;

    struct Player {
        uint256 balance;
        uint256 exitAmount;
        uint64 exitAt; // unix seconds; 0 = no pending exit
        bool everDeposited;
    }

    mapping(address => Player) public players;

    /// One-time authorization ids, consumed on use. Unordered by design:
    /// "did THIS authorization execute" must be answerable by one read.
    mapping(bytes32 => bool) public usedAuths;

    // ── events (names and fields mirror the Anchor program) ───────────────

    event Deposited(address indexed player, uint256 amount, uint256 balance);
    event Withdrawn(address indexed player, uint256 amount, uint256 balance, bool unilateral);
    event CheckpointApplied(uint256 indexed seq, uint256 playerCount, uint256 rake);
    event RakebackClaimed(address indexed player, uint256 amount, uint256 balance);
    event RakebackRedeemed(address indexed player, uint256 amount, uint256 rakeRemaining);
    event ExitRequested(address indexed player, uint256 amount, uint256 claimableAt);
    event ExitCancelled(address indexed player);
    event RakeWithdrawn(address indexed to, uint256 amount);
    event SettlerChanged(address indexed settler);
    event PausedSet(bool paused);
    event MaxRakeChanged(uint256 maxRake);
    event RakeDestinationChanged(address indexed destination);
    event MinDepositChanged(uint256 minDeposit);

    // ── errors (names mirror the Anchor error codes) ──────────────────────

    error BelowMinimumDeposit();
    error InvalidAmount();
    error InvalidExitDelay();
    error InsufficientBalance();
    error InsufficientRake();
    error CheckpointNotZeroSum();
    error CheckpointOutOfOrder();
    error TooManyEntries();
    error AccountCountMismatch();
    error DuplicatePlayer();
    error VaultUndercollateralised();
    error RakeTooLarge();
    error InvalidDestination();
    error NoPendingExit();
    error ExitNotReady();
    error EnforcedPause();
    error NotSettler();
    error NotAPlayer();
    error AuthUsed();
    error AuthExpired();
    error BadAuthSignature();

    // ── modifiers ─────────────────────────────────────────────────────────

    modifier whenNotPaused() {
        if (paused) revert EnforcedPause();
        _;
    }

    modifier onlySettler() {
        if (msg.sender != settler) revert NotSettler();
        _;
    }

    // ── construction ──────────────────────────────────────────────────────

    /// Mirrors `initialize`: the deployer is the authority, rake initially
    /// sweeps to them, the 500 USDG rake ceiling matches the program's
    /// default.
    constructor(IERC20 token_, address settler_, uint256 minDeposit_, uint256 exitDelay_)
        Ownable(msg.sender)
        EIP712("Suited", "1")
    {
        if (address(token_) == address(0) || settler_ == address(0)) revert InvalidDestination();
        if (minDeposit_ == 0) revert InvalidAmount();
        if (exitDelay_ == 0 || exitDelay_ > MAX_EXIT_DELAY) revert InvalidExitDelay();
        token = token_;
        settler = settler_;
        rakeDestination = msg.sender;
        maxRakePerCheckpoint = 500_000_000; // 500 USDG
        minDeposit = minDeposit_;
        exitDelay = exitDelay_;
    }

    // ── admin ─────────────────────────────────────────────────────────────

    function setSettler(address newSettler) external onlyOwner {
        if (newSettler == address(0)) revert InvalidDestination();
        settler = newSettler;
        emit SettlerChanged(newSettler);
    }

    function setPaused(bool paused_) external onlyOwner {
        paused = paused_;
        emit PausedSet(paused_);
    }

    function setMaxRake(uint256 maxRake) external onlyOwner {
        if (maxRake == 0) revert InvalidAmount();
        maxRakePerCheckpoint = maxRake;
        emit MaxRakeChanged(maxRake);
    }

    function setRakeDestination(address destination) external onlyOwner {
        if (destination == address(0)) revert InvalidDestination();
        rakeDestination = destination;
        emit RakeDestinationChanged(destination);
    }

    function setMinDeposit(uint256 minDeposit_) external onlyOwner {
        if (minDeposit_ == 0) revert InvalidAmount();
        minDeposit = minDeposit_;
        emit MinDepositChanged(minDeposit_);
    }

    /// Ownership moves ONLY via the two-step handover. A one-step renounce
    /// is the exact mistyped-authority brick the Solana program designed
    /// out: an ownerless contract can never rotate a compromised settler,
    /// pause, or sweep rake again. Player exits would survive — but the
    /// house would be permanently headless. Refused.
    function renounceOwnership() public view override onlyOwner {
        revert InvalidDestination();
    }

    /// Foreign ERC-20s mistakenly sent here would otherwise be stuck
    /// forever (the Solana vault's single-mint token account could not
    /// receive them at all). The money token itself is excluded — excess
    /// of it is collateral, deliberately unsweepable — and the destination
    /// is pinned to rakeDestination, so this expands nobody's reach over
    /// player funds.
    function rescueToken(IERC20 stray, uint256 amount) external onlyOwner {
        if (address(stray) == address(token)) revert InvalidDestination();
        stray.safeTransfer(rakeDestination, amount);
    }

    // ── deposits ──────────────────────────────────────────────────────────

    /// Permissionless. Credits what actually arrived, not what was asked
    /// for — a fee-on-transfer token must never inflate liabilities past
    /// the vault.
    function deposit(uint256 amount) external nonReentrant whenNotPaused {
        _deposit(amount);
    }

    /// One-transaction deposit for EIP-2612 tokens. The permit call is
    /// tolerated to fail: anyone can front-run a visible permit signature
    /// to consume its nonce, so we proceed whenever the allowance already
    /// covers the amount (the transferFrom below is the real gate).
    function depositWithPermit(uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s)
        external
        nonReentrant
        whenNotPaused
    {
        try IERC20Permit(address(token)).permit(msg.sender, address(this), amount, deadline, v, r, s) {} catch {}
        _deposit(amount);
    }

    function _deposit(uint256 amount) internal {
        if (amount < minDeposit) revert BelowMinimumDeposit();
        uint256 before = token.balanceOf(address(this));
        token.safeTransferFrom(msg.sender, address(this), amount);
        uint256 received = token.balanceOf(address(this)) - before;
        if (received < minDeposit) revert BelowMinimumDeposit();
        Player storage p = players[msg.sender];
        p.balance += received;
        p.everDeposited = true;
        liabilities += received;
        emit Deposited(msg.sender, received, p.balance);
    }

    // ── settlement ────────────────────────────────────────────────────────

    /// Apply one zero-sum batch of net results. Guards in the same order as
    /// the program: pause, entry count, length match, sequence, zero-sum,
    /// rake cap — then per-player application, then the solvency assert.
    ///
    /// The settler can move value between players and into rake. It cannot
    /// create value (zero-sum), replay or reorder batches (strict seq),
    /// touch one player twice in a batch (duplicate check), drive a balance
    /// negative (checked debit), or name a wallet that never deposited.
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
        for (uint256 i = 0; i < n; i++) {
            sum += deltas[i];
        }
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
            if (p.exitAmount > p.balance) p.exitAmount = p.balance;
        }

        checkpointSeq = seq;
        liabilities -= rake;
        rakeCollected += rake;

        if (token.balanceOf(address(this)) < liabilities + rakeCollected) {
            revert VaultUndercollateralised();
        }
        emit CheckpointApplied(seq, n, rake);
    }

    // ── rakeback ──────────────────────────────────────────────────────────

    /// Settler credits a player's in-contract balance from the rake pool.
    /// Pure balance-sheet move — no tokens leave; the solvency invariant is
    /// preserved by construction. The rakeback figure itself is off-chain
    /// accounting; what the chain enforces is that it comes out of rake
    /// actually collected, capped per call.
    function claimRakeback(address player, uint256 amount) external onlySettler whenNotPaused {
        if (amount == 0) revert InvalidAmount();
        Player storage p = players[player];
        if (!p.everDeposited) revert NotAPlayer();
        if (amount > rakeCollected) revert InsufficientRake();
        if (amount > maxRakePerCheckpoint) revert RakeTooLarge();
        rakeCollected -= amount;
        liabilities += amount;
        p.balance += amount;
        emit RakebackClaimed(player, amount, p.balance);
    }

    /// Rakeback straight to the player's wallet: the settler attests the
    /// figure with a one-time authorization, the player submits and is
    /// paid. Blocked by pause — this is house-funded money, unlike a
    /// withdrawal of the player's own balance.
    function redeemRakeback(uint256 amount, bytes32 authId, uint256 deadline, bytes calldata settlerSig)
        external
        nonReentrant
        whenNotPaused
    {
        if (amount == 0) revert InvalidAmount();
        if (!players[msg.sender].everDeposited) revert NotAPlayer();
        if (amount > rakeCollected) revert InsufficientRake();
        if (amount > maxRakePerCheckpoint) revert RakeTooLarge();
        _consumeAuth(REDEEM_AUTH_TYPEHASH, amount, authId, deadline, settlerSig);
        rakeCollected -= amount;
        _payOut(msg.sender, amount);
        emit RakebackRedeemed(msg.sender, amount, rakeCollected);
    }

    // ── withdrawals ───────────────────────────────────────────────────────

    /// The fast path out. The settler's signature attests "no chips in
    /// play" — the enforcement point the gateway's exposure checks feed.
    /// Deliberately NOT blocked by pause, and pays msg.sender only.
    function withdraw(uint256 amount, bytes32 authId, uint256 deadline, bytes calldata settlerSig)
        external
        nonReentrant
    {
        if (amount == 0) revert InvalidAmount();
        _consumeAuth(WITHDRAW_AUTH_TYPEHASH, amount, authId, deadline, settlerSig);
        Player storage p = players[msg.sender];
        if (p.balance < amount) revert InsufficientBalance();
        p.balance -= amount;
        if (p.exitAmount > p.balance) p.exitAmount = p.balance;
        liabilities -= amount;
        _payOut(msg.sender, amount);
        emit Withdrawn(msg.sender, amount, p.balance, false);
    }

    // ── the unilateral exit hatch ─────────────────────────────────────────

    /// Step 1: lock in an amount and start the clock. Needs only the
    /// player's key; survives pause. Calling again overwrites and restarts.
    function requestExit(uint256 amount) external {
        if (amount == 0) revert InvalidAmount();
        Player storage p = players[msg.sender];
        if (amount > p.balance) revert InsufficientBalance();
        p.exitAmount = amount;
        p.exitAt = uint64(block.timestamp + exitDelay);
        emit ExitRequested(msg.sender, amount, p.exitAt);
    }

    function cancelExit() external {
        Player storage p = players[msg.sender];
        p.exitAmount = 0;
        p.exitAt = 0;
        emit ExitCancelled(msg.sender);
    }

    /// Step 2: after the delay, take the money. Clamped to the current
    /// balance — hands settled during the wait may have reduced it; a
    /// losing player cannot exit with money they no longer have.
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

    // ── rake sweep ────────────────────────────────────────────────────────

    /// Owner sweeps collected rake — but only ever to `rakeDestination`.
    /// Not blocked by pause.
    function withdrawRake(uint256 amount) external onlyOwner nonReentrant {
        if (amount == 0) revert InvalidAmount();
        if (amount > rakeCollected) revert InsufficientRake();
        rakeCollected -= amount;
        address to = rakeDestination;
        _payOut(to, amount);
        emit RakeWithdrawn(to, amount);
    }

    // ── internals ─────────────────────────────────────────────────────────

    /// Verify and consume a one-time settler authorization. The struct
    /// binds the player as msg.sender, so an authorization issued for one
    /// wallet is worthless to any other; the EIP-712 domain binds chainId
    /// and this contract's address, so it is worthless on any other chain
    /// or deployment.
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

    /// The single place custody is exercised, mirroring transfer_from_vault:
    /// the vault must cover THIS amount (not full solvency — see the note on
    /// `liabilities`), so a shortfall fails loudly instead of partially paying.
    function _payOut(address to, uint256 amount) internal {
        if (token.balanceOf(address(this)) < amount) revert VaultUndercollateralised();
        token.safeTransfer(to, amount);
    }
}

