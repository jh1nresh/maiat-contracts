// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {TokenSafetyHook} from "../contracts/hooks/TokenSafetyHook.sol";
import {ITokenSafetyOracle} from "../contracts/interfaces/ITokenSafetyOracle.sol";
import {IACPHook} from "../contracts/IACPHook.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/*//////////////////////////////////////////////////////////////
                        MOCK CONTRACTS
//////////////////////////////////////////////////////////////*/

contract MockTokenSafetyOracle is ITokenSafetyOracle {
    mapping(address => TokenSafetyData) public tokenData;

    function setTokenData(
        address token,
        TokenVerdict verdict,
        uint256 buyTax,
        uint256 sellTax,
        bool verified
    ) external {
        tokenData[token] = TokenSafetyData({
            verdict: verdict,
            buyTax: buyTax,
            sellTax: sellTax,
            verified: verified,
            lastUpdated: block.timestamp
        });
    }

    function getTokenSafety(address token) external view override returns (TokenSafetyData memory) {
        return tokenData[token];
    }
}

/// @dev Mock ACP contract for access control testing
contract MockACP {
    IACPHook public hook;

    function setHook(address hook_) external {
        hook = IACPHook(hook_);
    }

    function callBeforeAction(uint256 jobId, bytes4 selector, bytes memory data) external {
        hook.beforeAction(jobId, selector, data);
    }

    function callAfterAction(uint256 jobId, bytes4 selector, bytes memory data) external {
        hook.afterAction(jobId, selector, data);
    }
}

/*//////////////////////////////////////////////////////////////
                        UNIT TESTS
//////////////////////////////////////////////////////////////*/

contract TokenSafetyHookUnitTest is Test {
    TokenSafetyHook public impl;
    TokenSafetyHook public hook;
    MockTokenSafetyOracle public oracle;
    MockACP public acp;

    address public owner = makeAddr("owner");
    address public safeToken = makeAddr("safeToken");
    address public honeypotToken = makeAddr("honeypotToken");
    address public highTaxToken = makeAddr("highTaxToken");
    address public unverifiedToken = makeAddr("unverifiedToken");
    address public blockedToken = makeAddr("blockedToken");

    bytes4 public constant FUND_SEL = bytes4(keccak256("fund(uint256,uint256,bytes)"));
    bytes4 public constant SUBMIT_SEL = bytes4(keccak256("submit(uint256,bytes32,bytes)"));

    // Default blocked: Honeypot | HighTax | Blocked = 0b10110 = 22
    uint8 public constant DEFAULT_BLOCKED = 22;

    function setUp() public {
        oracle = new MockTokenSafetyOracle();
        acp = new MockACP();

        // Set up token data
        oracle.setTokenData(safeToken, ITokenSafetyOracle.TokenVerdict.Safe, 0, 0, true);
        oracle.setTokenData(honeypotToken, ITokenSafetyOracle.TokenVerdict.Honeypot, 10000, 10000, true);
        oracle.setTokenData(highTaxToken, ITokenSafetyOracle.TokenVerdict.HighTax, 3000, 3000, true);
        oracle.setTokenData(unverifiedToken, ITokenSafetyOracle.TokenVerdict.Unverified, 0, 0, false);
        oracle.setTokenData(blockedToken, ITokenSafetyOracle.TokenVerdict.Blocked, 0, 0, true);

        // Deploy hook behind proxy
        impl = new TokenSafetyHook();
        bytes memory initData = abi.encodeCall(
            TokenSafetyHook.initialize,
            (address(oracle), address(acp), DEFAULT_BLOCKED, owner)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        hook = TokenSafetyHook(address(proxy));

        acp.setHook(address(hook));
    }

    /*//////////////////////////////////////////////////////////////
                        CONSTRUCTOR / INITIALIZER
    //////////////////////////////////////////////////////////////*/

    function test_impl_cannotBeInitialized() public {
        vm.expectRevert();
        impl.initialize(address(oracle), address(acp), DEFAULT_BLOCKED, owner);
    }

    function test_initialize_zeroOracle() public {
        TokenSafetyHook newImpl = new TokenSafetyHook();
        vm.expectRevert(TokenSafetyHook.TokenSafetyHook__ZeroAddress.selector);
        new ERC1967Proxy(address(newImpl), abi.encodeCall(
            TokenSafetyHook.initialize, (address(0), address(acp), DEFAULT_BLOCKED, owner)
        ));
    }

    function test_initialize_zeroACP() public {
        TokenSafetyHook newImpl = new TokenSafetyHook();
        vm.expectRevert(TokenSafetyHook.TokenSafetyHook__ZeroAddress.selector);
        new ERC1967Proxy(address(newImpl), abi.encodeCall(
            TokenSafetyHook.initialize, (address(oracle), address(0), DEFAULT_BLOCKED, owner)
        ));
    }

    function test_initialize_values() public view {
        assertEq(address(hook.s_oracle()), address(oracle));
        assertEq(hook.s_agenticCommerce(), address(acp));
        assertEq(hook.s_blockedVerdicts(), DEFAULT_BLOCKED);
        assertEq(hook.owner(), owner);
    }

    /*//////////////////////////////////////////////////////////////
                        ACCESS CONTROL
    //////////////////////////////////////////////////////////////*/

    function test_beforeAction_revertNotACP() public {
        vm.prank(makeAddr("random"));
        vm.expectRevert(TokenSafetyHook.TokenSafetyHook__OnlyAgenticCommerce.selector);
        hook.beforeAction(1, FUND_SEL, abi.encode(safeToken));
    }

    function test_afterAction_revertNotACP() public {
        vm.prank(makeAddr("random"));
        vm.expectRevert(TokenSafetyHook.TokenSafetyHook__OnlyAgenticCommerce.selector);
        hook.afterAction(1, FUND_SEL, bytes(""));
    }

    /*//////////////////////////////////////////////////////////////
                        SAFE TOKEN PASSES
    //////////////////////////////////////////////////////////////*/

    function test_beforeAction_fund_safeToken_passes() public {
        acp.callBeforeAction(1, FUND_SEL, abi.encode(safeToken));
        // No revert = pass
    }

    function test_beforeAction_emits_TokenChecked() public {
        vm.expectEmit(true, true, false, true);
        emit TokenSafetyHook.TokenChecked(1, safeToken, ITokenSafetyOracle.TokenVerdict.Safe, true);
        acp.callBeforeAction(1, FUND_SEL, abi.encode(safeToken));
    }

    /*//////////////////////////////////////////////////////////////
                        HONEYPOT TOKEN REVERTS
    //////////////////////////////////////////////////////////////*/

    function test_beforeAction_fund_honeypotToken_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(
            TokenSafetyHook.TokenSafetyHook__UnsafeToken.selector,
            honeypotToken,
            uint8(ITokenSafetyOracle.TokenVerdict.Honeypot)
        ));
        acp.callBeforeAction(1, FUND_SEL, abi.encode(honeypotToken));
    }

    function test_beforeAction_fund_highTaxToken_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(
            TokenSafetyHook.TokenSafetyHook__UnsafeToken.selector,
            highTaxToken,
            uint8(ITokenSafetyOracle.TokenVerdict.HighTax)
        ));
        acp.callBeforeAction(1, FUND_SEL, abi.encode(highTaxToken));
    }

    function test_beforeAction_fund_blockedToken_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(
            TokenSafetyHook.TokenSafetyHook__UnsafeToken.selector,
            blockedToken,
            uint8(ITokenSafetyOracle.TokenVerdict.Blocked)
        ));
        acp.callBeforeAction(1, FUND_SEL, abi.encode(blockedToken));
    }

    /*//////////////////////////////////////////////////////////////
                        WHITELISTED TOKEN BYPASSES ORACLE
    //////////////////////////////////////////////////////////////*/

    function test_beforeAction_whitelisted_bypasses_oracle() public {
        // Whitelist the honeypot token
        vm.prank(owner);
        hook.setWhitelisted(honeypotToken, true);

        // Should pass even though it's a honeypot
        vm.expectEmit(true, true, false, true);
        emit TokenSafetyHook.TokenChecked(1, honeypotToken, ITokenSafetyOracle.TokenVerdict.Safe, true);
        acp.callBeforeAction(1, FUND_SEL, abi.encode(honeypotToken));
    }

    function test_setWhitelisted_emitsEvent() public {
        vm.prank(owner);
        vm.expectEmit(true, false, false, true);
        emit TokenSafetyHook.TokenWhitelisted(safeToken, true);
        hook.setWhitelisted(safeToken, true);
    }

    function test_setWhitelistedBatch() public {
        address[] memory tokens = new address[](2);
        tokens[0] = honeypotToken;
        tokens[1] = highTaxToken;

        vm.prank(owner);
        hook.setWhitelistedBatch(tokens, true);

        assertTrue(hook.isWhitelisted(honeypotToken));
        assertTrue(hook.isWhitelisted(highTaxToken));

        // Both should pass now
        acp.callBeforeAction(1, FUND_SEL, abi.encode(honeypotToken));
        acp.callBeforeAction(2, FUND_SEL, abi.encode(highTaxToken));
    }

    /*//////////////////////////////////////////////////////////////
                        RISK TOLERANCE (BLOCKED VERDICTS)
    //////////////////////////////////////////////////////////////*/

    function test_unverified_passes_by_default() public {
        // Default blocked = Honeypot | HighTax | Blocked (not Unverified)
        acp.callBeforeAction(1, FUND_SEL, abi.encode(unverifiedToken));
    }

    function test_setBlockedVerdicts_blocksUnverified() public {
        // Add Unverified to blocked verdicts
        // Current: 0b10110 (22), add bit 3: 0b11110 (30)
        uint8 newBlocked = DEFAULT_BLOCKED | (1 << 3);
        vm.prank(owner);
        hook.setBlockedVerdicts(newBlocked);

        vm.expectRevert(abi.encodeWithSelector(
            TokenSafetyHook.TokenSafetyHook__UnsafeToken.selector,
            unverifiedToken,
            uint8(ITokenSafetyOracle.TokenVerdict.Unverified)
        ));
        acp.callBeforeAction(1, FUND_SEL, abi.encode(unverifiedToken));
    }

    function test_setBlockedVerdicts_allowsHoneypot() public {
        // Remove Honeypot from blocked verdicts
        // Current: 0b10110 (22), remove bit 1: 0b10100 (20)
        uint8 newBlocked = DEFAULT_BLOCKED & uint8(~uint8(1 << 1));
        vm.prank(owner);
        hook.setBlockedVerdicts(newBlocked);

        // Honeypot should now pass
        acp.callBeforeAction(1, FUND_SEL, abi.encode(honeypotToken));
    }

    function test_isVerdictBlocked() public view {
        assertFalse(hook.isVerdictBlocked(ITokenSafetyOracle.TokenVerdict.Safe));
        assertTrue(hook.isVerdictBlocked(ITokenSafetyOracle.TokenVerdict.Honeypot));
        assertTrue(hook.isVerdictBlocked(ITokenSafetyOracle.TokenVerdict.HighTax));
        assertFalse(hook.isVerdictBlocked(ITokenSafetyOracle.TokenVerdict.Unverified));
        assertTrue(hook.isVerdictBlocked(ITokenSafetyOracle.TokenVerdict.Blocked));
    }

    /*//////////////////////////////////////////////////////////////
                        NON-FUND SELECTORS PASS THROUGH
    //////////////////////////////////////////////////////////////*/

    function test_beforeAction_nonFund_passes() public {
        // Submit selector should pass through even with honeypot token
        acp.callBeforeAction(1, SUBMIT_SEL, abi.encode(honeypotToken, bytes32(0), bytes("")));
    }

    function test_afterAction_passthrough() public {
        // afterAction should always pass (no-op)
        acp.callAfterAction(1, FUND_SEL, bytes(""));
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_setOracle() public {
        address newOracle = makeAddr("newOracle");
        vm.prank(owner);
        vm.expectEmit(true, true, false, false);
        emit TokenSafetyHook.OracleUpdated(address(oracle), newOracle);
        hook.setOracle(newOracle);
        assertEq(address(hook.s_oracle()), newOracle);
    }

    function test_setOracle_revertZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(TokenSafetyHook.TokenSafetyHook__ZeroAddress.selector);
        hook.setOracle(address(0));
    }

    function test_setOracle_revertNotOwner() public {
        vm.prank(makeAddr("random"));
        vm.expectRevert();
        hook.setOracle(makeAddr("newOracle"));
    }

    function test_setAgenticCommerce() public {
        address newACP = makeAddr("newACP");
        vm.prank(owner);
        vm.expectEmit(true, true, false, false);
        emit TokenSafetyHook.AgenticCommerceUpdated(address(acp), newACP);
        hook.setAgenticCommerce(newACP);
        assertEq(hook.s_agenticCommerce(), newACP);
    }

    function test_setAgenticCommerce_revertZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(TokenSafetyHook.TokenSafetyHook__ZeroAddress.selector);
        hook.setAgenticCommerce(address(0));
    }

    function test_setBlockedVerdicts_emitsEvent() public {
        vm.prank(owner);
        vm.expectEmit(false, false, false, true);
        emit TokenSafetyHook.BlockedVerdictsUpdated(DEFAULT_BLOCKED, 0);
        hook.setBlockedVerdicts(0);
    }

    /*//////////////////////////////////////////////////////////////
                        ERC-165
    //////////////////////////////////////////////////////////////*/

    function test_supportsInterface_IACPHook() public view {
        assertTrue(hook.supportsInterface(type(IACPHook).interfaceId));
    }

    function test_supportsInterface_ERC165() public view {
        assertTrue(hook.supportsInterface(0x01ffc9a7));
    }

    function test_supportsInterface_random() public view {
        assertFalse(hook.supportsInterface(0xdeadbeef));
    }

    /*//////////////////////////////////////////////////////////////
                        EDGE CASES
    //////////////////////////////////////////////////////////////*/

    function test_beforeAction_emptyData_passes() public {
        // Empty data should skip token check
        acp.callBeforeAction(1, FUND_SEL, bytes(""));
    }

    function test_beforeAction_zeroAddressToken_skipped() public {
        // Zero address token should skip check
        acp.callBeforeAction(1, FUND_SEL, abi.encode(address(0)));
    }

    /*//////////////////////////////////////////////////////////////
                        FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_randomTokenAddress_randomVerdict(
        address token,
        uint8 verdictRaw
    ) public {
        vm.assume(token != address(0));
        // Bound verdict to valid range (0-4)
        ITokenSafetyOracle.TokenVerdict verdict = ITokenSafetyOracle.TokenVerdict(verdictRaw % 5);

        oracle.setTokenData(token, verdict, 0, 0, true);

        uint8 verdictValue = uint8(verdict);
        bool shouldBlock = (DEFAULT_BLOCKED & uint8(1 << verdictValue)) != 0;

        if (shouldBlock) {
            vm.expectRevert(abi.encodeWithSelector(
                TokenSafetyHook.TokenSafetyHook__UnsafeToken.selector,
                token,
                verdictValue
            ));
        }
        acp.callBeforeAction(1, FUND_SEL, abi.encode(token));
    }

    function testFuzz_randomRiskTolerance(uint8 blockedMask) public {
        vm.prank(owner);
        hook.setBlockedVerdicts(blockedMask);

        // Test each verdict
        for (uint8 v = 0; v < 5; v++) {
            address token = address(uint160(v + 100));
            ITokenSafetyOracle.TokenVerdict verdict = ITokenSafetyOracle.TokenVerdict(v);
            oracle.setTokenData(token, verdict, 0, 0, true);

            bool shouldBlock = (blockedMask & (1 << v)) != 0;

            if (shouldBlock) {
                vm.expectRevert(abi.encodeWithSelector(
                    TokenSafetyHook.TokenSafetyHook__UnsafeToken.selector,
                    token,
                    v
                ));
            }
            acp.callBeforeAction(uint256(v), FUND_SEL, abi.encode(token));
        }
    }

    function testFuzz_whitelist_bypassesAllVerdicts(
        address token,
        uint8 verdictRaw
    ) public {
        vm.assume(token != address(0));
        ITokenSafetyOracle.TokenVerdict verdict = ITokenSafetyOracle.TokenVerdict(verdictRaw % 5);

        // Set to honeypot or any unsafe verdict
        oracle.setTokenData(token, verdict, 10000, 10000, true);

        // Whitelist it
        vm.prank(owner);
        hook.setWhitelisted(token, true);

        // Should pass regardless of verdict
        acp.callBeforeAction(1, FUND_SEL, abi.encode(token));
    }

    function testFuzz_setOracle(address newOracle) public {
        vm.assume(newOracle != address(0));
        vm.prank(owner);
        hook.setOracle(newOracle);
        assertEq(address(hook.s_oracle()), newOracle);
    }

    function testFuzz_setAgenticCommerce(address newACP) public {
        vm.assume(newACP != address(0));
        vm.prank(owner);
        hook.setAgenticCommerce(newACP);
        assertEq(hook.s_agenticCommerce(), newACP);
    }

    function testFuzz_supportsInterface(bytes4 interfaceId) public view {
        bool expected = (interfaceId == type(IACPHook).interfaceId) || (interfaceId == 0x01ffc9a7);
        assertEq(hook.supportsInterface(interfaceId), expected);
    }
}
