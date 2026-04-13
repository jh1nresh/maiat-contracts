// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {AgenticCommerceHooked} from "../contracts/AgenticCommerceHooked.sol";
import {TrustUpdateHook, IDojoTrustScore} from "../contracts/hooks/TrustUpdateHook.sol";
import {AttestationHook, IEAS, IAgenticCommerceReader} from "../contracts/hooks/AttestationHook.sol";
import {CompositeRouterHook} from "../contracts/hooks/CompositeRouterHook.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";

/*//////////////////////////////////////////////////////////////
                        MOCK CONTRACTS
//////////////////////////////////////////////////////////////*/

contract CASMockEAS is IEAS {
    uint256 public attestCount;
    bool public shouldRevert;
    bytes32 public lastRecipient32;
    bool public lastCompleted;

    function setShouldRevert(bool v) external { shouldRevert = v; }

    function attest(AttestationRequest calldata request) external payable override returns (bytes32) {
        if (shouldRevert) revert("EAS_REVERTED");
        attestCount++;
        // Decode completed flag from attestation data for assertions
        (,,,,,, bool completed) = abi.decode(
            request.data.data,
            (uint256, address, address, address, uint256, bytes32, bool)
        );
        lastCompleted = completed;
        return keccak256(abi.encode(attestCount));
    }
}

contract CASMockDojoTrustScore is IDojoTrustScore {
    uint256 public updateCount;
    address public lastSubject;
    uint16 public lastEvaluatorSuccess;
    bool public shouldRevert;

    function setShouldRevert(bool v) external { shouldRevert = v; }

    function updateScore(
        address subject,
        bytes32, /* vertical */
        uint16 evaluatorSuccess,
        uint16, uint16, uint16, uint16,
        uint32
    ) external override {
        if (shouldRevert) revert("TRUST_REVERTED");
        updateCount++;
        lastSubject = subject;
        lastEvaluatorSuccess = evaluatorSuccess;
    }
}

/*//////////////////////////////////////////////////////////////
                CLOSE AND SETTLE TESTS
//////////////////////////////////////////////////////////////*/

contract CloseAndSettleTest is Test {
    AgenticCommerceHooked acp;
    TrustUpdateHook trustHook;
    AttestationHook attestHook;
    CompositeRouterHook router;
    CASMockEAS eas;
    CASMockDojoTrustScore trustScore;
    ERC20Mock usdc;

    // Gateway: a signing key we control in tests
    uint256 gatewayKey = 0xA11CE_B00B5_CAFE_BEEF_1234_5678_9ABC_DEF0;
    address gateway;

    address admin    = makeAddr("admin");
    address client   = makeAddr("client");
    address provider = makeAddr("provider");
    address evaluator = makeAddr("evaluator");
    address treasury = makeAddr("treasury");

    bytes32 constant BAS_SCHEMA_UID = keccak256("SessionEvaluation");
    uint256 constant BUDGET = 10e18; // 10 USDC
    uint256 constant FEE_BP = 500;   // 5%

    function setUp() public {
        gateway = vm.addr(gatewayKey);

        // USDC mock
        usdc = new ERC20Mock();
        usdc.mint(client, 1000e18);

        // ACP core
        vm.prank(admin);
        acp = new AgenticCommerceHooked(address(usdc), treasury);

        vm.startPrank(admin);
        acp.setPlatformFee(FEE_BP, treasury);
        acp.setTrustedGateway(gateway);
        vm.stopPrank();

        // Mocks
        eas = new CASMockEAS();
        trustScore = new CASMockDojoTrustScore();

        // AttestationHook
        attestHook = new AttestationHook(address(acp), address(eas), BAS_SCHEMA_UID);

        // TrustUpdateHook
        trustHook = new TrustUpdateHook(address(acp), address(trustScore));

        // CompositeRouterHook (upgradeable)
        CompositeRouterHook impl = new CompositeRouterHook();
        bytes memory initData = abi.encodeCall(CompositeRouterHook.initialize, (address(acp), admin));
        router = CompositeRouterHook(address(new ERC1967Proxy(address(impl), initData)));

        vm.startPrank(admin);
        router.addPlugin(address(attestHook),  10);
        router.addPlugin(address(trustHook),   20);
        vm.stopPrank();

        // Fund client
        vm.prank(client);
        usdc.approve(address(acp), type(uint256).max);
    }

    // --- Helpers ---

    /// @dev Creates a funded job with no hook (for pure closeAndSettle tests).
    function _createFundedJob() internal returns (uint256 jobId) {
        vm.prank(client);
        jobId = acp.createJob(provider, evaluator, block.timestamp + 1 days, "test", address(0));

        vm.prank(client);
        acp.setBudget(jobId, BUDGET, "");

        vm.prank(client);
        acp.fund(jobId, BUDGET, "");
    }

    /// @dev Creates a funded job wired to a specific hook contract directly.
    ///      Used for hook integration tests — hooks expect msg.sender == acp,
    ///      so they must be called via acp directly (not via router).
    function _createFundedJobWith(address hook) internal returns (uint256 jobId) {
        vm.prank(client);
        jobId = acp.createJob(provider, evaluator, block.timestamp + 1 days, "test", hook);

        vm.prank(client);
        acp.setBudget(jobId, BUDGET, "");

        vm.prank(client);
        acp.fund(jobId, BUDGET, "");
    }

    function _sign(uint256 jobId, uint8 finalScore, uint16 callCount, uint8 passRate)
        internal view returns (bytes memory sig)
    {
        bytes32 digest = keccak256(abi.encodePacked(block.chainid, address(acp), jobId, finalScore, callCount, passRate));
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(digest);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(gatewayKey, ethHash);
        sig = abi.encodePacked(r, s, v);
    }

    // --- Core happy path tests ---

    function test_closeAndSettle_pass_releasesPayment() public {
        uint256 jobId = _createFundedJob();
        uint8 passRate = 100;
        bytes memory sig = _sign(jobId, 100, 5, passRate);

        uint256 providerBefore = usdc.balanceOf(provider);
        uint256 treasuryBefore = usdc.balanceOf(treasury);
        uint256 clientBefore   = usdc.balanceOf(client);

        vm.prank(client);
        acp.closeAndSettle(jobId, 100, 5, passRate, sig);

        // Provider gets 95%, treasury gets 5%
        uint256 fee = (BUDGET * FEE_BP) / 10000;
        uint256 net = BUDGET - fee;
        assertEq(usdc.balanceOf(provider), providerBefore + net,     "provider net");
        assertEq(usdc.balanceOf(treasury), treasuryBefore + fee,     "treasury fee");
        assertEq(usdc.balanceOf(client),   clientBefore,             "client unchanged");

        // Job is Completed
        AgenticCommerceHooked.Job memory job = acp.getJob(jobId);
        assertEq(uint8(job.status), uint8(AgenticCommerceHooked.JobStatus.Completed));
    }

    function test_closeAndSettle_fail_refundsClient() public {
        uint256 jobId = _createFundedJob();
        uint8 passRate = 40; // < 80 threshold -> FAIL
        bytes memory sig = _sign(jobId, 40, 5, passRate);

        uint256 clientBefore   = usdc.balanceOf(client);
        uint256 providerBefore = usdc.balanceOf(provider);

        vm.prank(client);
        acp.closeAndSettle(jobId, 40, 5, passRate, sig);

        // Client gets full refund
        assertEq(usdc.balanceOf(client),   clientBefore + BUDGET,   "client refund");
        assertEq(usdc.balanceOf(provider), providerBefore,          "provider unchanged");

        // Job is Rejected
        AgenticCommerceHooked.Job memory job = acp.getJob(jobId);
        assertEq(uint8(job.status), uint8(AgenticCommerceHooked.JobStatus.Rejected));
    }

    function test_closeAndSettle_atExactThreshold_passes() public {
        uint256 jobId = _createFundedJob();
        uint8 passRate = 80; // exactly PASS_THRESHOLD
        bytes memory sig = _sign(jobId, 80, 3, passRate);

        vm.prank(client);
        acp.closeAndSettle(jobId, 80, 3, passRate, sig);

        AgenticCommerceHooked.Job memory job = acp.getJob(jobId);
        assertEq(uint8(job.status), uint8(AgenticCommerceHooked.JobStatus.Completed));
    }

    function test_closeAndSettle_belowThreshold_fails() public {
        uint256 jobId = _createFundedJob();
        uint8 passRate = 79; // just below threshold -> FAIL
        bytes memory sig = _sign(jobId, 60, 3, passRate);

        vm.prank(client);
        acp.closeAndSettle(jobId, 60, 3, passRate, sig);

        AgenticCommerceHooked.Job memory job = acp.getJob(jobId);
        assertEq(uint8(job.status), uint8(AgenticCommerceHooked.JobStatus.Rejected));
    }

    // --- Event tests ---

    function test_closeAndSettle_emitsJobSettled_pass() public {
        uint256 jobId = _createFundedJob();
        bytes memory sig = _sign(jobId, 100, 5, 100);

        vm.expectEmit(true, true, false, true);
        emit AgenticCommerceHooked.JobSettled(jobId, client, 100, true);

        vm.prank(client);
        acp.closeAndSettle(jobId, 100, 5, 100, sig);
    }

    function test_closeAndSettle_emitsJobSettled_fail() public {
        uint256 jobId = _createFundedJob();
        bytes memory sig = _sign(jobId, 30, 2, 30);

        vm.expectEmit(true, true, false, true);
        emit AgenticCommerceHooked.JobSettled(jobId, client, 30, false);

        vm.prank(client);
        acp.closeAndSettle(jobId, 30, 2, 30, sig);
    }

    // --- Access control & validation ---

    function test_closeAndSettle_reverts_ifNotClient() public {
        uint256 jobId = _createFundedJob();
        bytes memory sig = _sign(jobId, 100, 5, 100);

        vm.prank(provider); // wrong caller
        vm.expectRevert(AgenticCommerceHooked.Unauthorized.selector);
        acp.closeAndSettle(jobId, 100, 5, 100, sig);
    }

    function test_closeAndSettle_reverts_ifNotFunded() public {
        // Job is Open, not yet funded
        vm.prank(client);
        uint256 jobId = acp.createJob(provider, evaluator, block.timestamp + 1 days, "test", address(0));

        vm.prank(client);
        acp.setBudget(jobId, BUDGET, "");

        bytes memory sig = _sign(jobId, 100, 5, 100);

        vm.prank(client);
        vm.expectRevert(AgenticCommerceHooked.WrongStatus.selector);
        acp.closeAndSettle(jobId, 100, 5, 100, sig);
    }

    function test_closeAndSettle_reverts_ifAlreadySettled() public {
        uint256 jobId = _createFundedJob();
        bytes memory sig = _sign(jobId, 100, 5, 100);

        vm.prank(client);
        acp.closeAndSettle(jobId, 100, 5, 100, sig);

        // Second settle attempt — status is now Completed
        vm.prank(client);
        vm.expectRevert(AgenticCommerceHooked.WrongStatus.selector);
        acp.closeAndSettle(jobId, 100, 5, 100, sig);
    }

    function test_closeAndSettle_reverts_invalidGatewaySignature() public {
        uint256 jobId = _createFundedJob();

        // Sign with wrong key
        uint256 wrongKey = 0xDEAD;
        bytes32 digest = keccak256(abi.encodePacked(block.chainid, address(acp), jobId, uint8(100), uint16(5), uint8(100)));
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(digest);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, ethHash);
        bytes memory badSig = abi.encodePacked(r, s, v);

        vm.prank(client);
        vm.expectRevert(AgenticCommerceHooked.InvalidGatewaySignature.selector);
        acp.closeAndSettle(jobId, 100, 5, 100, badSig);
    }

    function test_closeAndSettle_reverts_signatureOverDifferentParams() public {
        uint256 jobId = _createFundedJob();
        // Sign passRate=100 but submit passRate=40
        bytes memory sig = _sign(jobId, 100, 5, 100);

        vm.prank(client);
        vm.expectRevert(AgenticCommerceHooked.InvalidGatewaySignature.selector);
        acp.closeAndSettle(jobId, 100, 5, 40, sig); // passRate differs
    }

    function test_closeAndSettle_reverts_ifGatewayNotSet() public {
        // Deploy fresh ACP without setting gateway
        AgenticCommerceHooked freshAcp = new AgenticCommerceHooked(address(usdc), treasury);
        vm.prank(address(this));
        freshAcp.setPlatformFee(FEE_BP, treasury);

        vm.prank(address(this));
        uint256 jobId = freshAcp.createJob(provider, evaluator, block.timestamp + 1 days, "test", address(0));
        freshAcp.setBudget(jobId, BUDGET, "");

        usdc.mint(address(this), BUDGET);
        usdc.approve(address(freshAcp), BUDGET);
        freshAcp.fund(jobId, BUDGET, "");

        bytes memory sig = _sign(jobId, 100, 5, 100);

        vm.expectRevert(AgenticCommerceHooked.TrustedGatewayNotSet.selector);
        freshAcp.closeAndSettle(jobId, 100, 5, 100, sig);
    }

    // --- Hook integration ---

    function test_closeAndSettle_triggersAttestationHook_onPass() public {
        uint256 jobId = _createFundedJobWith(address(attestHook));
        bytes memory sig = _sign(jobId, 95, 5, 100);

        vm.prank(client);
        acp.closeAndSettle(jobId, 95, 5, 100, sig);

        assertEq(eas.attestCount(), uint256(1), "attestation written");
        assertTrue(eas.lastCompleted(), "attestation completed=true");
    }

    function test_closeAndSettle_triggersAttestationHook_onFail() public {
        uint256 jobId = _createFundedJobWith(address(attestHook));
        bytes memory sig = _sign(jobId, 20, 3, 20);

        vm.prank(client);
        acp.closeAndSettle(jobId, 20, 3, 20, sig);

        assertEq(eas.attestCount(), uint256(1), "attestation written");
        assertFalse(eas.lastCompleted(), "attestation completed=false");
    }

    function test_closeAndSettle_triggersTrustUpdateHook_onPass() public {
        uint256 jobId = _createFundedJobWith(address(trustHook));
        bytes memory sig = _sign(jobId, 90, 5, 100);

        vm.prank(client);
        acp.closeAndSettle(jobId, 90, 5, 100, sig);

        assertEq(trustScore.updateCount(), uint256(1), "trust updated");
        assertEq(trustScore.lastSubject(), provider, "correct subject");
        assertEq(uint256(trustScore.lastEvaluatorSuccess()), uint256(10000), "100 passRate -> 10000 bps");
    }

    function test_closeAndSettle_triggersTrustUpdateHook_onFail() public {
        uint256 jobId = _createFundedJobWith(address(trustHook));
        bytes memory sig = _sign(jobId, 30, 3, 40);

        vm.prank(client);
        acp.closeAndSettle(jobId, 30, 3, 40, sig);

        assertEq(trustScore.updateCount(), uint256(1), "trust updated on fail");
        assertEq(uint256(trustScore.lastEvaluatorSuccess()), uint256(4000), "40 passRate -> 4000 bps");
    }

    function test_closeAndSettle_settlementNotRevertedIfHookFails() public {
        eas.setShouldRevert(true);
        trustScore.setShouldRevert(true);

        uint256 jobId = _createFundedJobWith(address(attestHook));
        bytes memory sig = _sign(jobId, 100, 5, 100);

        // Should not revert even though hooks fail
        vm.prank(client);
        acp.closeAndSettle(jobId, 100, 5, 100, sig);

        // Job still settled correctly
        AgenticCommerceHooked.Job memory job = acp.getJob(jobId);
        assertEq(uint8(job.status), uint8(AgenticCommerceHooked.JobStatus.Completed));
    }

    // --- Admin ---

    function test_setTrustedGateway_onlyAdmin() public {
        address newGw = makeAddr("newGateway");

        vm.prank(client); // not admin
        vm.expectRevert();
        acp.setTrustedGateway(newGw);

        vm.prank(admin);
        acp.setTrustedGateway(newGw);
        assertEq(acp.trustedGateway(), newGw);
    }

    function test_passThreshold_constant() public view {
        assertEq(uint256(acp.PASS_THRESHOLD()), uint256(80));
    }
}
