// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../BaseACPHook.sol";

/**
 * @title TrustUpdateHook
 * @notice Calls DojoTrustScore.updateScore() after every completed or rejected job
 *         that was settled via closeAndSettle() (i.e. carries evaluation data in optParams).
 *
 * USE CASE
 * --------
 * When an agent or human calls closeAndSettle(), the gateway-signed proof includes
 * passRate and callCount. This hook extracts that evaluation data from optParams
 * and updates the provider's on-chain trust score on DojoTrustScore.
 *
 * FLOW
 * ----
 *  1. closeAndSettle() → status → payment → afterAction(SEL_COMPLETE | SEL_REJECT, hookData)
 *     hookData = abi.encode(bytes32(passRate), abi.encode(passRate, callCount, finalScore))
 *  2. BaseACPHook routes to _postComplete or _postReject
 *  3. TrustUpdateHook decodes optParams → calls dojoTrustScore.updateScore()
 *     Uses try/catch — DojoTrustScore failures never block settlement
 *
 * TRUST MODEL
 * -----------
 * - This hook must hold EVALUATOR_ROLE on DojoTrustScore to call updateScore().
 *   Grant post-deploy: dojoTrustScore.grantRole(EVALUATOR_ROLE, trustUpdateHook)
 * - Falls back gracefully if optParams is empty (called from old complete()/reject() path).
 * - Non-hookable path (claimRefund) is intentionally excluded.
 *
 * @custom:security-contact security@erc-8183.org
 */

/// @notice Minimal interface for DojoTrustScore.updateScore()
interface IDojoTrustScore {
    function updateScore(
        address subject,
        bytes32 vertical,
        uint16 evaluatorSuccess,
        uint16 buyerAvgRating,
        uint16 sellerAvgBehavior,
        uint16 volumeScore,
        uint16 uptimeScore,
        uint32 sessionCount
    ) external;
}

/// @notice Minimal read interface to fetch job.provider from AgenticCommerceHooked
interface IACJobReader {
    struct Job {
        uint256 id;
        address client;
        address provider;
        address evaluator;
        address hook;
        string description;
        uint256 budget;
        uint256 expiredAt;
        uint8 status;
    }
    function getJob(uint256 jobId) external view returns (Job memory);
}

contract TrustUpdateHook is BaseACPHook {
    /*//////////////////////////////////////////////////////////////
                            CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev bytes32("dojo") — left-aligned, right-padded with zeros
    bytes32 public constant DOJO_VERTICAL =
        0x646f6a6f00000000000000000000000000000000000000000000000000000000;

    /// @dev Minimum abi.encode(uint8, uint16, uint8) length = 3 * 32 = 96 bytes
    uint256 private constant MIN_OPT_PARAMS_LEN = 96;

    /*//////////////////////////////////////////////////////////////
                            STORAGE
    //////////////////////////////////////////////////////////////*/

    IDojoTrustScore public immutable dojoTrustScore;
    IACJobReader public immutable acReader;

    /*//////////////////////////////////////////////////////////////
                            EVENTS
    //////////////////////////////////////////////////////////////*/

    event TrustUpdated(
        uint256 indexed jobId,
        address indexed provider,
        uint8 passRate,
        uint16 evaluatorSuccessBps
    );
    event TrustUpdateSkipped(uint256 indexed jobId, string reason);
    event TrustUpdateFailed(uint256 indexed jobId, bytes err);

    /*//////////////////////////////////////////////////////////////
                            ERRORS
    //////////////////////////////////////////////////////////////*/

    error TrustUpdateHook__ZeroAddress();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @param acpContract_      AgenticCommerceHooked address
     * @param dojoTrustScore_   DojoTrustScore contract address
     */
    constructor(
        address acpContract_,
        address dojoTrustScore_
    ) BaseACPHook(acpContract_) {
        if (dojoTrustScore_ == address(0)) revert TrustUpdateHook__ZeroAddress();
        dojoTrustScore = IDojoTrustScore(dojoTrustScore_);
        acReader = IACJobReader(acpContract_);
    }

    /*//////////////////////////////////////////////////////////////
                    HOOK: POST-COMPLETE (PASS)
    //////////////////////////////////////////////////////////////*/

    function _postComplete(
        uint256 jobId,
        bytes32, /* reason */
        bytes memory optParams
    ) internal override {
        _doUpdate(jobId, optParams);
    }

    /*//////////////////////////////////////////////////////////////
                    HOOK: POST-REJECT (FAIL)
    //////////////////////////////////////////////////////////////*/

    function _postReject(
        uint256 jobId,
        bytes32, /* reason */
        bytes memory optParams
    ) internal override {
        _doUpdate(jobId, optParams);
    }

    /*//////////////////////////////////////////////////////////////
                    CORE: UPDATE TRUST SCORE
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Decodes evaluation data from optParams (set by closeAndSettle only),
     *      fetches the job provider, and calls dojoTrustScore.updateScore().
     *      Silently skips if optParams is too short (old complete()/reject() path).
     *      Uses try/catch — failures never revert the settlement tx.
     *
     * optParams format (from closeAndSettle):
     *   abi.encode(uint8 passRate, uint16 callCount, uint8 finalScore)
     *   = 96 bytes (3 × 32-byte ABI slots)
     */
    function _doUpdate(uint256 jobId, bytes memory optParams) internal {
        // Skip if no evaluation data (old evaluator path)
        if (optParams.length < MIN_OPT_PARAMS_LEN) {
            emit TrustUpdateSkipped(jobId, "no optParams");
            return;
        }

        // Decode evaluation data
        (uint8 passRate, , ) = abi.decode(optParams, (uint8, uint16, uint8));

        // Get provider address from ACP contract
        address provider;
        try acReader.getJob(jobId) returns (IACJobReader.Job memory j) {
            provider = j.provider;
        } catch (bytes memory err) {
            emit TrustUpdateFailed(jobId, err);
            return;
        }

        if (provider == address(0)) {
            emit TrustUpdateSkipped(jobId, "zero provider");
            return;
        }

        // passRate 0-100 → evaluatorSuccess 0-10000 bps (clamped to uint16 max)
        uint16 evaluatorSuccessBps = uint16(uint256(passRate) * 100);

        try dojoTrustScore.updateScore(
            provider,
            DOJO_VERTICAL,
            evaluatorSuccessBps,
            0,  // buyerAvgRating   — Phase 2
            0,  // sellerAvgBehavior — Phase 2
            0,  // volumeScore       — Phase 2
            0,  // uptimeScore       — Phase 2
            1   // sessionCount      — increment per session
        ) {
            emit TrustUpdated(jobId, provider, passRate, evaluatorSuccessBps);
        } catch (bytes memory err) {
            emit TrustUpdateFailed(jobId, err);
        }
    }

    /*//////////////////////////////////////////////////////////////
                    ERC-165
    //////////////////////////////////////////////////////////////*/

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IACPHook).interfaceId
            || interfaceId == 0x01ffc9a7; // IERC165
    }
}
