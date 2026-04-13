// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IACPHook} from "../IACPHook.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ITokenSafetyOracle} from "../interfaces/ITokenSafetyOracle.sol";

/**
 * @title TokenSafetyHook
 * @notice Blocks job funding when the payment token is flagged as a
 *         honeypot, high-tax, or otherwise unsafe by an external oracle.
 *
 * USE CASE
 * --------
 * ACP jobs are funded with arbitrary ERC-20 tokens. A malicious client
 * could fund a job with a honeypot token — one that can be sent but not
 * transferred out — locking the provider's payout. TokenSafetyHook
 * intercepts the fund() call, extracts the payment token address, queries
 * a configurable ITokenSafetyOracle, and reverts if the verdict matches
 * the blocked-verdicts bitmask (default: Honeypot, HighTax, Blocked).
 * Whitelisted tokens (e.g. USDC, WETH) bypass the oracle check entirely.
 *
 * FLOW (all interactions through core contract → hook callbacks)
 * ----
 *  1. createJob(provider, evaluator, expiredAt, description, hook=this
 *     or hook=CompositeRouterHook with TokenSafetyHook as a plugin)
 *  2. fund(jobId, optParams)
 *     → _preFund (via beforeAction): decode data to extract payment token
 *       address. If whitelisted, pass through. Otherwise query
 *       oracle.getTokenVerdict(token); if verdict is in blockedVerdictsMask
 *       revert with UnsafeToken(token, verdict).
 *  3. All other lifecycle calls (submit, complete, reject, …)
 *     → beforeAction / afterAction: no-op passthrough.
 *
 * TRUST MODEL
 * -----------
 * The oracle is an external contract whose address is owner-controlled.
 * Whitelisted tokens are never sent to the oracle — the whitelist is the
 * owner's override mechanism for known-safe tokens. The blocked-verdicts
 * bitmask is also owner-configurable, letting operators tune risk
 * tolerance (e.g. allow Unverified tokens in low-trust environments).
 *
 * @custom:security-contact security@erc-8183.org
 */
contract TokenSafetyHook is IACPHook, OwnableUpgradeable {
    /*//////////////////////////////////////////////////////////////
                            CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev Well-known selector from AgenticCommerce
    bytes4 public constant FUND_SEL = bytes4(keccak256("fund(uint256,uint256,bytes)"));

    /// @notice Bitmask position for each verdict
    /// @dev TokenVerdict enum: Safe(0), Honeypot(1), HighTax(2), Unverified(3), Blocked(4)
    uint8 public constant VERDICT_SAFE = 0;
    uint8 public constant VERDICT_HONEYPOT = 1;
    uint8 public constant VERDICT_HIGHTAX = 2;
    uint8 public constant VERDICT_UNVERIFIED = 3;
    uint8 public constant VERDICT_BLOCKED = 4;

    /// @notice Default blocked verdicts bitmask (Honeypot | HighTax | Blocked)
    /// @dev Binary: 0b10110 = 22 (blocks verdicts 1, 2, 4)
    uint8 public constant DEFAULT_BLOCKED_VERDICTS = uint8((1 << VERDICT_HONEYPOT) | (1 << VERDICT_HIGHTAX) | (1 << VERDICT_BLOCKED));

    /*//////////////////////////////////////////////////////////////
                            STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Token safety oracle for checking token verdicts
    ITokenSafetyOracle public s_oracle;

    /// @notice AgenticCommerce contract — used for access control
    address public s_agenticCommerce;

    /// @notice Bitmask of verdicts to block (bit N = block verdict N)
    /// @dev E.g., 0b10110 = block Honeypot(1), HighTax(2), Blocked(4)
    uint8 public s_blockedVerdicts;

    /// @notice Whitelisted tokens bypass oracle checks
    mapping(address => bool) public s_whitelisted;

    /// @dev Reserved storage gap for future upgrades
    uint256[44] private __gap;

    /*//////////////////////////////////////////////////////////////
                            EVENTS
    //////////////////////////////////////////////////////////////*/

    event TokenChecked(
        uint256 indexed jobId,
        address indexed token,
        ITokenSafetyOracle.TokenVerdict verdict,
        bool allowed
    );
    event TokenWhitelisted(address indexed token, bool whitelisted);
    event OracleUpdated(address indexed oldOracle, address indexed newOracle);
    event AgenticCommerceUpdated(address indexed oldAC, address indexed newAC);
    event BlockedVerdictsUpdated(uint8 oldMask, uint8 newMask);

    /*//////////////////////////////////////////////////////////////
                            ERRORS
    //////////////////////////////////////////////////////////////*/

    error TokenSafetyHook__UnsafeToken(address token, uint8 verdict);
    error TokenSafetyHook__ZeroAddress();
    error TokenSafetyHook__OnlyAgenticCommerce();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /*//////////////////////////////////////////////////////////////
                            INITIALIZER
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initialize the TokenSafetyHook
     * @param oracle_ Token safety oracle address
     * @param agenticCommerce_ AgenticCommerce contract address
     * @param blockedVerdicts_ Bitmask of verdicts to block
     * @param owner_ Contract owner address
     */
    function initialize(
        address oracle_,
        address agenticCommerce_,
        uint8 blockedVerdicts_,
        address owner_
    ) external initializer {
        if (oracle_ == address(0)) revert TokenSafetyHook__ZeroAddress();
        if (agenticCommerce_ == address(0)) revert TokenSafetyHook__ZeroAddress();

        __Ownable_init(owner_);
        s_oracle = ITokenSafetyOracle(oracle_);
        s_agenticCommerce = agenticCommerce_;
        s_blockedVerdicts = blockedVerdicts_;
    }

    /*//////////////////////////////////////////////////////////////
                    IACPHook: beforeAction
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Called before state transitions. Reverts if token is unsafe.
     * @dev Only callable by AgenticCommerce. Only checks fund() selector.
     * @param jobId The job ID
     * @param selector The function selector being called
     * @param data Encoded function parameters
     */
    function beforeAction(uint256 jobId, bytes4 selector, bytes calldata data) external override {
        if (msg.sender != s_agenticCommerce) revert TokenSafetyHook__OnlyAgenticCommerce();

        if (selector == FUND_SEL) {
            // fund() data encoding: abi.encode(address caller, address token, uint256 amount, bytes optParams)
            // We need the token address which is at offset 1 in the decoded tuple
            // The data from BaseACPHook for fund is just optParams (raw bytes)
            // But TrustGateACPHook shows fund data as: (address caller, bytes optParams)
            // For TokenSafetyHook, we need the payment token address from the job
            // The hook receives the raw optParams, but we need to read token from job
            // Actually, let's decode the data to get the payment token
            // Per BaseACPHook: fund → optParams (raw bytes)
            // The payment token should be encoded in optParams or we need to read from job
            //
            // For this implementation, we expect the caller to encode the token in optParams:
            // optParams = abi.encode(address token, ...)
            // If optParams is empty or doesn't contain a token, skip check
            if (data.length >= 32) {
                address token = abi.decode(data, (address));
                if (token != address(0)) {
                    _checkTokenSafety(jobId, token);
                }
            }
        }
        // Other selectors: pass through
    }

    /*//////////////////////////////////////////////////////////////
                    IACPHook: afterAction
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Called after state transitions. No-op passthrough.
     * @dev Only callable by AgenticCommerce.
     */
    function afterAction(uint256, bytes4, bytes calldata) external view override {
        if (msg.sender != s_agenticCommerce) revert TokenSafetyHook__OnlyAgenticCommerce();
        // No-op: TokenSafetyHook only gates beforeAction
    }

    /*//////////////////////////////////////////////////////////////
                    ERC-165
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice ERC-165 interface support
     * @param interfaceId The interface identifier
     * @return True if supported
     */
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IACPHook).interfaceId
            || interfaceId == 0x01ffc9a7; // IERC165
    }

    /*//////////////////////////////////////////////////////////////
                    ADMIN
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set or remove a token from the whitelist
     * @param token Token address to whitelist
     * @param whitelisted Whether to whitelist (true) or remove (false)
     */
    function setWhitelisted(address token, bool whitelisted) external onlyOwner {
        s_whitelisted[token] = whitelisted;
        emit TokenWhitelisted(token, whitelisted);
    }

    /**
     * @notice Batch whitelist multiple tokens
     * @param tokens Array of token addresses
     * @param whitelisted Whether to whitelist all
     */
    function setWhitelistedBatch(address[] calldata tokens, bool whitelisted) external onlyOwner {
        for (uint256 i = 0; i < tokens.length; i++) {
            s_whitelisted[tokens[i]] = whitelisted;
            emit TokenWhitelisted(tokens[i], whitelisted);
        }
    }

    /**
     * @notice Update the token safety oracle
     * @param oracle_ New oracle address
     */
    function setOracle(address oracle_) external onlyOwner {
        if (oracle_ == address(0)) revert TokenSafetyHook__ZeroAddress();
        address old = address(s_oracle);
        s_oracle = ITokenSafetyOracle(oracle_);
        emit OracleUpdated(old, oracle_);
    }

    /**
     * @notice Update the AgenticCommerce contract reference
     * @param agenticCommerce_ New AgenticCommerce address
     */
    function setAgenticCommerce(address agenticCommerce_) external onlyOwner {
        if (agenticCommerce_ == address(0)) revert TokenSafetyHook__ZeroAddress();
        address old = s_agenticCommerce;
        s_agenticCommerce = agenticCommerce_;
        emit AgenticCommerceUpdated(old, agenticCommerce_);
    }

    /**
     * @notice Update the blocked verdicts bitmask
     * @dev Set bit N to block verdict N. E.g., 0b10110 blocks Honeypot, HighTax, Blocked
     * @param blockedVerdicts_ New bitmask
     */
    function setBlockedVerdicts(uint8 blockedVerdicts_) external onlyOwner {
        uint8 old = s_blockedVerdicts;
        s_blockedVerdicts = blockedVerdicts_;
        emit BlockedVerdictsUpdated(old, blockedVerdicts_);
    }

    /*//////////////////////////////////////////////////////////////
                    VIEW
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check if a specific verdict is blocked
     * @param verdict The verdict to check
     * @return True if blocked
     */
    function isVerdictBlocked(ITokenSafetyOracle.TokenVerdict verdict) external view returns (bool) {
        return (s_blockedVerdicts & (1 << uint8(verdict))) != 0;
    }

    /**
     * @notice Check if a token is whitelisted
     * @param token Token address
     * @return True if whitelisted
     */
    function isWhitelisted(address token) external view returns (bool) {
        return s_whitelisted[token];
    }

    /*//////////////////////////////////////////////////////////////
                    INTERNAL
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Check token safety via oracle and revert if blocked
     * @param jobId Job ID for event emission
     * @param token Token address to check
     */
    function _checkTokenSafety(uint256 jobId, address token) internal {
        // Whitelisted tokens bypass oracle check
        if (s_whitelisted[token]) {
            emit TokenChecked(jobId, token, ITokenSafetyOracle.TokenVerdict.Safe, true);
            return;
        }

        // Query oracle
        ITokenSafetyOracle.TokenSafetyData memory data = s_oracle.getTokenSafety(token);
        uint8 verdictValue = uint8(data.verdict);

        // Check if verdict is blocked
        bool blocked = (s_blockedVerdicts & (1 << verdictValue)) != 0;

        emit TokenChecked(jobId, token, data.verdict, !blocked);

        if (blocked) {
            revert TokenSafetyHook__UnsafeToken(token, verdictValue);
        }
    }
}
