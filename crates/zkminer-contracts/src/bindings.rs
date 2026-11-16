use alloy::sol;

// Bindings for the HemiProve v2 stack deployed on Hemi testnet 743111 on 2026-11-16
// (hemiprove-contracts 3bc441d, the deployed 8e1808b apart from its LICENSE). Every item here is
// pinned against the vendored ABI JSON in `hemiprove-abi/` by `tests` below: a struct whose layout
// drifts from the deployed contract still DECODES (alloy's call decoding does not validate a static
// return's field order), it just yields the wrong values — so the pin is what keeps a renamed or
// reordered field from becoming a silent misread.
sol! {
    // ═══════════════════════════════════════════════════════════════════════════
    // Shared Types
    // ═══════════════════════════════════════════════════════════════════════════

    #[derive(Debug, PartialEq, Eq)]
    struct JobDescriptor {
        bytes32 programId;
        bytes32 proofSystemId;
        address callbackContract;
        address assignedProver;
        bytes32 tag;
        bytes inputData;
        bytes callbackExtraData;
        bytes extraVerifierData;
        // Journal binding (zkminer-chain `binding`): with `journalFields == 0` a non-zero hash is the
        // FULL statement hash `keccak256(abi.encode(JOURNAL_PREDICATE_DOMAIN_V1, proofSystemId,
        // programId, publicValues))`; with `journalFields != 0` it is the FIELDS hash over the byte
        // ranges `journalFields` names. Both zero is a NONE job, which requires an `assignedProver`.
        bytes32 expectedJournalHash;
        // 8 slots of `(uint16 offset << 16) | uint16 length`, slot 0 the top 32 bits. Slot 0 may
        // instead hold a binding marker: 0xffffffff (journal prefix `jobId ‖ prover`) or 0xfffffffe
        // (SP1 proof nonce at seal bytes 68..100).
        bytes32 journalFields;
    }

    #[derive(Debug, PartialEq, Eq)]
    struct HashedDescriptor {
        bytes32 programId;
        bytes32 proofSystemId;
        address callbackContract;
        address assignedProver;
        bytes32 tag;
        bytes32 inputDataHash;
        bytes32 expectedJournalHash;
        bytes32 journalFields;
    }

    #[derive(Debug)]
    struct AuctionConfig {
        uint96 minPrice;
        uint96 maxPrice;
        uint40 rampUpPeriod;
        uint8 curveType;
        uint40 fulfillmentTimeout;
        uint96 lockCollateralBps;
        uint96 speedPremium;
        uint40 exclusivityDuration;
        uint32 callbackGasLimit;
        bool excludeFromEwma;
        bool laxCallbackMode;
    }

    #[derive(Debug)]
    struct ProverStake {
        uint128 totalStaked;
        uint128 lockedCollateral;
        uint128 unstakeAmount;
        uint40 unstakeRequestTime;
        // A BLOCK NUMBER (not a timestamp): a claim needs `block.number > depositBlock`
        // (`StakingBlockDelayNotMet` otherwise).
        uint40 depositBlock;
    }

    #[derive(Debug)]
    struct ProverStats {
        uint64 jobsFulfilled;
        uint64 jobsSlashed;
        uint64 jobsReleased;
        uint96 totalEarned;
        uint40 firstFulfillmentAt;
        uint40 lastFulfillmentAt;
    }

    #[derive(Debug)]
    struct UnionClock {
        uint40 anchor;
        uint40 total;
        bool registryPaused;
        uint40 firstPauseA;
        uint40 firstPauseR;
        uint40 graceEndMax;
        uint24 epochA;
        uint24 epochR;
    }

    #[derive(Debug)]
    struct KeyClock {
        bool active;
        uint40 a;
        uint40 t;
        uint40 c;
        uint24 epoch;
        uint40 prevEnd;
    }

    #[derive(Debug)]
    struct ClockMarks {
        uint40 routerIdleSince;
        uint40 registryPauseStart;
        uint40 registryGraceEnd;
    }

    #[derive(Debug)]
    struct AdapterEntry {
        address adapter;
        uint8 status;
        uint40 deprecatedAt;
        bytes32 successorId;
        uint96 defaultCollateralRatio;
        uint128 minStake;
        uint16 feeRateBps;
        uint8 cycleAttestationMode;
    }

    // 22 members. `lockDeadline` and `bidDeadline` are EFFECTIVE (pause-credited); `slashOpensAt` is
    // `lockDeadline + PROVER_GRACE + 31` for a Locked job and 0 otherwise. (Removed vs. the July ABI:
    // `totalProverReward`; added: `slashOpensAt`. Same word count, so a stale binding misreads every
    // member from index 6 on without any decode error.)
    #[derive(Debug)]
    struct JobStatusView {
        uint8 status;
        address caller;
        address prover;
        uint96 currentAuctionPrice;
        uint96 depositedAmount;
        uint96 bonusAmount;
        uint96 settledPrice;
        uint96 speedPremium;
        uint40 lockDeadline;
        uint40 timeRemaining;
        uint40 auctionTimeElapsed;
        uint40 rampUpPeriod;
        uint8 reopenCount;
        uint8 callbackRejections;
        bytes32 proofSystemId;
        bytes32 descriptorHash;
        address currentBidder;
        uint96 currentBid;
        uint40 bidDeadline;
        uint64 expectedCycles;
        uint8 verifierTrust;
        uint40 slashOpensAt;
    }

    #[derive(Debug)]
    struct VerifiedResult {
        bytes32 programId;
        bytes32 proofSystemId;
        bytes32 publicValuesHash;
        bytes32 descriptorHash;
        address prover;
        uint40 fulfilledAt;
        uint8 reopenCount;
        uint8 trust;
    }

    #[derive(Debug)]
    struct CycleConfig {
        uint64 expectedCycles;
        uint96 cycleCommitCollateral;
        uint8 snapshotMode;
        uint16 snapshotToleranceBps;
        uint16 snapshotFullBonusOvershootBps;
        uint16 snapshotUndershootPenaltyBps;
        uint16 snapshotFullPenaltyUndershootBps;
        uint16 snapshotResolverRewardBps;
    }

    #[derive(Debug)]
    struct CompetitiveBidConfig {
        uint40 underbidWindow;
        uint40 maxBiddingDuration;
        uint40 maxBidExtension;
        uint96 minBidDecrement;
        uint8 bidExtensionCurveType;
    }

    #[derive(Debug)]
    struct BidState {
        address currentBidder;
        address biddingOperator;
        uint96 currentBid;
        uint40 bidDeadline;
        uint40 firstBidTime;
        uint96 softLockedCollateral;
        uint40 wallBidDeadline;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // HemiProveCore — Submission + Claiming
    // ═══════════════════════════════════════════════════════════════════════════

    #[sol(rpc)]
    #[derive(Debug)]
    interface IHemiProveCore {
        event JobSubmitted(
            bytes32 indexed jobId, bytes32 indexed proofSystemId, address indexed caller,
            bytes32 programId, bytes32 descriptorHash, uint96 depositedAmount,
            uint96 minPrice, uint96 maxPrice, uint40 fulfillmentTimeout, uint8 trust
        );
        // `lockDeadline` here is RAW (not pause-credited): never schedule from it.
        event JobClaimed(
            bytes32 indexed jobId, address indexed prover, address indexed operator,
            uint96 settledPrice, uint96 bonusAmount, uint40 lockDeadline
        );
        event PayoutCredited(address indexed recipient, bytes32 jobId, uint256 amount);

        function submitJob(
            JobDescriptor calldata descriptor,
            AuctionConfig calldata config,
            CycleConfig calldata cycleConfig,
            CompetitiveBidConfig calldata bidConfig
        ) external returns (bytes32 jobId);

        function submitJobDefault(
            bytes32 programId,
            bytes32 proofSystemId,
            bytes calldata inputData,
            address callbackContract,
            bytes32 expectedJournalHash,
            bytes32 journalFields
        ) external returns (bytes32 jobId);

        // First-class convenience entry points that emit the SAME JobSubmitted event and
        // produce ordinary Open jobs — descriptor recovery MUST decode these too, or a
        // job submitted via them is claimed (collateral locked) but can never be fulfilled.
        function submitJobSimple(
            JobDescriptor calldata descriptor,
            bytes32 presetName
        ) external returns (bytes32 jobId);

        function submitJobBatch(
            JobDescriptor[] calldata descriptors,
            AuctionConfig[] calldata configs,
            CycleConfig[] calldata cycleConfigs,
            CompetitiveBidConfig[] calldata bidConfigs
        ) external returns (bytes32[] jobIds);

        // A claim states the lowest price and premium cap it accepts; the router reverts
        // `ClaimBelowFloor` if either has fallen below them at inclusion. The exact `priceFloor` is
        // the return value of an `eth_call` of `claimJob(jobId, 0, 0)` from the prover at a mined
        // block; `premiumFloor` is `getPremiumCap(jobId)` at that same block.
        function claimJob(bytes32 jobId, uint96 priceFloor, uint96 premiumFloor) external returns (uint96 price);
        function claimJobDelegated(bytes32 jobId, address prover, uint96 priceFloor, uint96 premiumFloor) external returns (uint96 price);
        // Batch-lock up to MAX_BATCH_SIZE (10) jobs in one tx. Partial-completion: a per-job
        // failure is reported as `false` in the returned bool[] (with no reason) and the outer tx
        // still succeeds. zkminer does not batch-claim (see `no_batch` in run.rs).
        function claimJobBatch(bytes32[] jobIds, uint96[] priceFloors, uint96[] premiumFloors) external returns (bool[] results);
        function topUpDeposit(bytes32 jobId, uint96 amount) external;
        function withdraw() external;
        function jobIndex() external view returns (uint48);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // HemiProveFulfill — Fulfillment, Slash, Release, Cancel
    // ═══════════════════════════════════════════════════════════════════════════

    #[sol(rpc)]
    #[derive(Debug)]
    interface IHemiProveFulfill {
        event JobFulfilled(
            bytes32 indexed jobId, address indexed prover, address indexed caller,
            uint96 settledPrice, uint96 bonusAmount, uint256 proverPayout,
            uint256 callerRefund, uint256 protocolFee, uint256 speedBonus,
            uint64 actualCycles, bytes publicValues
        );
        event JobReleased(
            bytes32 indexed jobId, address indexed prover, uint256 penaltyAmount,
            uint96 newBonusAmount, uint256 timeHeld, address operator
        );
        event JobReopened(
            bytes32 indexed jobId, address indexed slashedProver, address indexed slashCaller,
            uint128 slashedAmount, uint256 keeperReward, uint256 burnedAmount,
            uint96 newBonusAmount, uint8 reopenCount, uint40 newRampUpStart,
            uint40 elapsedAtLock, address operator
        );
        event JobCancelled(bytes32 indexed jobId, address indexed caller, uint256 refundAmount, uint256 bonusBurned);
        event GracePauseReleased(bytes32 indexed jobId, address indexed prover, uint128 releasedCollateral, address operator);
        event GraceReleased(bytes32 indexed jobId, address indexed prover, bytes32 proofSystemId, uint128 releasedCollateral, address operator);
        event DeadlineExtended(bytes32 indexed jobId, uint40 extension, uint40 lockDeadline);

        function fulfillJob(
            bytes32 jobId,
            JobDescriptor calldata descriptor,
            bytes calldata publicValues,
            bytes calldata proofBytes
        ) external;

        function fulfillJobHashed(
            bytes32 jobId,
            HashedDescriptor calldata hashedDesc,
            bytes calldata callbackExtraData,
            bytes calldata extraVerifierData,
            bytes calldata publicValues,
            bytes calldata proofBytes
        ) external;

        function releaseJob(bytes32 jobId) external;
        function graceRelease(bytes32 jobId) external;
        function gracePauseRelease(bytes32 jobId) external;
        function slashAndReopen(bytes32 jobId) external;
        function slashAndClaim(bytes32 jobId, uint96 priceFloor) external returns (uint96 price);
        function cancelJob(bytes32 jobId) external;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // HemiProveAux — Views, Bidding, Pause state
    // ═══════════════════════════════════════════════════════════════════════════

    #[sol(rpc)]
    #[derive(Debug)]
    interface IHemiProveAux {
        // `Paused`/`Unpaused` share topic0 across the router, Registry and Staking: filter by address.
        event Paused(address account);
        event Unpaused(address account);

        // The union pause clock of base A ("the router or the Registry is paused"). `u.anchor` above
        // the block timestamp means a RESUME_GRACE is still running after a lift.
        function getUnionClock() external view returns (UnionClock memory u, ClockMarks memory m);
        // One key of the union clock: a psId's adapter Disabled windows. `!active && a > now` means a
        // key RESUME_GRACE is still running after the adapter was re-enabled (a key lift does not move
        // the base anchor).
        function getKeyClock(bytes32 key) external view returns (KeyClock memory);

        // Governance-set per-job collateral floor (Constants.MIN_COLLATERAL_AMOUNT). A job's own
        // floor is snapshotted at submit: read it with `getJobSnapshots`.
        function MIN_COLLATERAL_AMOUNT() external view returns (uint256);
        function getCurrentPrice(bytes32 jobId) external view returns (uint96);
        function getJobStatusView(bytes32 jobId) external view returns (JobStatusView memory);
        // Raw job record. The deployed getter returns 27 STATIC outputs — more than alloy's 24-tuple
        // `SolType` limit — so it is bound as the identical 27-word encoding and decoded (with
        // per-word range validation) by [`JobRecord::from_words`]. Selectors depend on inputs only.
        // `lockDeadline` in it is RAW (not pause-credited).
        function jobs(bytes32 jobId) external view returns (bytes32[27] words);
        function getJobExtras(bytes32 jobId) external view returns (uint256 pauseCredit, uint40 pauseBase, bool assignedOnly);
        function getJobSnapshots(bytes32 jobId) external view returns (uint256 releasePenaltyBps, uint256 minCollateral, uint256 collateralBps);
        function getPremiumCap(bytes32 jobId) external view returns (uint256);
        function previewSpeedBonus(bytes32 jobId) external view returns (uint256);
        function getProofNonce(bytes32 jobId, address prover) external view returns (uint256 nonce, uint32[4] limbs);
        function bidConfigs(bytes32 jobId) external view returns (
            uint40 underbidWindow, uint40 maxBiddingDuration, uint40 maxBidExtension,
            uint96 minBidDecrement, uint8 bidExtensionCurveType
        );
        function jobAssignedProvers(bytes32 jobId) external view returns (address);
        function jobProofSystems(bytes32 jobId) external view returns (bytes32);
        function isPendingSettlement(bytes32 jobId) external view returns (bool);
        function paused() external view returns (bool);
        function staking() external view returns (address);
        function registry() external view returns (address);
        function hemiToken() external view returns (address);
        function getVerifiedResult(bytes32 jobId) external view returns (
            bytes32 programId, bytes32 proofSystemId, bytes32 publicValuesHash,
            address prover, uint40 fulfilledAt, bytes32 descriptorHash,
            uint8 trust, uint8 reopenCount, bool exists
        );
        function suggestPriceRange(bytes32 proofSystemId, bytes32 programId) external view returns (
            uint96 suggestedMin, uint96 suggestedMax, bool stale
        );
        function getBidState(bytes32 jobId) external view returns (BidState memory);
        function submitBid(bytes32 jobId, uint96 bidAmount) external;
        function settleBid(bytes32 jobId) external;

        // A competitive bid on `jobId`. A witness simulation of the job stops on it (design §5.2):
        // zkminer does not bid in Phase 1, and once a bid is live the caller can no longer cancel.
        event BidSubmitted(
            bytes32 indexed jobId, address indexed bidder, uint96 bidAmount, uint40 newBidDeadline,
            address operator, address previousBidder
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Router upgrade timelock (HemiProve.sol). One pending operation at a time: an upgrade, a facet
    // update, or both, named by its `operationHash`. Watched by the governance watcher (design §5.5):
    // no witness lock whose deadline falls after a pending upgrade's `readyAt`.
    // ═══════════════════════════════════════════════════════════════════════════

    #[sol(rpc)]
    #[derive(Debug)]
    interface IHemiProveRouterGov {
        event UpgradeProposed(bytes32 indexed operationHash, uint48 readyAt);
        event UpgradeCancelled(bytes32 indexed operationHash);
        event UpgradeExecuted(bytes32 indexed operationHash);

        // `(0, 0)` when nothing is pending.
        function pendingUpgrade() external view returns (bytes32 operationHash, uint48 readyAt);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Errors a prover must classify (router facets + Staking). Decoded from revert data by
    // zkminer-chain `revert` — a typed 4-byte selector is the only reliable signal, because the
    // router answers every adapter failure with the bare `VerifierCallFailed()` and a substring
    // match on the message text cannot tell a pause from a proof defect.
    // ═══════════════════════════════════════════════════════════════════════════

    #[derive(Debug)]
    interface IHemiProveErrors {
        // Claim
        error EnforcedPause();
        error NotAuthorizedOperator(address operator, address prover, uint256 permission);
        error DelegatedClaimCooldownActive(bytes32 jobId, uint40 cooldownEnd);
        error NotReserved(bytes32 jobId);
        error JobNotOpen(bytes32 jobId);
        error JobNotFound(bytes32 jobId);
        error MaxReopenCountReached(bytes32 jobId, uint8 reopenCount);
        error BiddingActive(bytes32 jobId);
        error CompetitiveBiddingActive(bytes32 jobId);
        error ReleaseCooldownActive(bytes32 jobId, address prover, uint256 cooldownEnd);
        error AdapterDisabled(bytes32 proofSystemId);
        error AdapterNotActive(bytes32 proofSystemId);
        error RegistryPaused(bytes32 jobId);
        error BlacklistedVerifier(address verifier);
        error CustomVerifierHasNoCode(address verifier);
        error InsufficientStake(address prover, uint128 required, uint128 actual);
        error StakingBlockDelayNotMet(address prover, uint40 depositBlock);
        error ExclusivityActive(bytes32 jobId, address assignedProver);
        error ClaimBelowFloor(bytes32 jobId, uint96 price, uint96 priceFloor, uint256 premiumCap, uint96 premiumFloor);
        error CollateralOverflow(uint256 collateral);
        error PendingUnstakeConflict(address prover);
        error OperatorCollateralCapExceeded(address prover, address operator, uint128 cap, uint128 requested);
        // Fulfil
        error JobNotLocked(bytes32 jobId);
        error NotJobProver(bytes32 jobId, address prover);
        error InvalidDescriptorHash(bytes32 expected, bytes32 actual);
        error JournalTooLarge(uint256 length, uint256 max);
        error JournalPrefixMismatch(bytes32 jobId, address prover);
        error ProofNonceMismatch(uint256 expected, uint256 actual);
        error JournalMismatch(bytes32 expected, bytes32 actual);
        error InsufficientGasForFullSettlement();
        error InsufficientGasForSettlement();
        error VerifierCallFailed();
        error PendingSettlement(bytes32 jobId);
        error ReentrancyGuardReentrantCall();
        error JobAlreadyTerminal(bytes32 jobId);
        // Release / slash / grace exits
        error UseGraceRelease(bytes32 jobId);
        error UseGraceReleaseWithDescriptor(bytes32 jobId);
        error RegistryPausedUseGracePauseRelease();
        error SystemPausedUseGracePauseRelease();
        error GracePauseDelayNotMet(bytes32 jobId, uint40 requiredAfter);
        error JobExpiredBeforePause(bytes32 jobId);
        error NoGovernanceCause(bytes32 jobId);
        error JobNotExpired(bytes32 jobId);
        // Submit (a job zkminer itself submits)
        error InvalidJournalBinding(uint8 reason);
        // Staking
        error InsufficientFreeStake(address prover, uint128 requested, uint128 available);
        error NoStake(address prover);
        error Unauthorized();
        error ZeroAmount();
        error NoPendingUnstake(address prover);
        error UnstakeNotReady(address prover, uint40 readyAt);
        error PostActivityCooldownActive(address prover, uint40 unlockAt);
        error MaxTotalStakedExceeded(uint256 newTotal, uint256 max);
        // Token
        error OwnableUnauthorizedAccount(address account);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // HemiProveStaking
    // ═══════════════════════════════════════════════════════════════════════════

    #[sol(rpc)]
    #[derive(Debug)]
    interface IHemiProveStaking {
        event Staked(address indexed prover, uint128 amount, uint128 newTotal);
        event UnstakeRequested(address indexed prover, uint128 amount, uint40 withdrawAfter);
        event Withdrawn(address indexed prover, uint128 amount, uint128 newTotal);
        event StakeReduced(address indexed prover, uint128 amount, uint128 newTotal, uint128 newPendingUnstake, bool slashed);

        function stake(address prover, uint128 amount) external;
        function requestUnstake(uint128 amount) external;
        function withdrawUnstaked() external;
        function cancelUnstake() external;
        function getProverStake(address prover) external view returns (ProverStake memory);
        function getAvailableCollateral(address prover) external view returns (uint128);
        function getProverStats(address prover) external view returns (ProverStats memory);
        function hemiToken() external view returns (address);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // HemiProveRegistry
    // ═══════════════════════════════════════════════════════════════════════════

    #[sol(rpc)]
    #[derive(Debug)]
    interface IHemiProveRegistry {
        event AdapterDisabledEvent(bytes32 indexed proofSystemId);
        // Emitted by the instant re-enable AND by `executePendingReactivation` (the verifier swap
        // landing): either way the adapter is enabled again, at `adapter`.
        event AdapterReactivated(bytes32 indexed proofSystemId, address adapter);
        event AdapterRegistered(
            bytes32 indexed proofSystemId, address adapter, uint16 feeRateBps, uint128 minStake,
            uint96 defaultCollateralRatio, uint8 cycleAttestationMode
        );
        // A verifier swap for a Disabled adapter, executable from `readyAt` (the switch delay: 48 h by
        // default, governable from 1 h to 30 days). A new proposal replaces a pending one, emitting
        // `VerifierSwitchCancelled` for the old one first.
        event VerifierSwitchProposed(bytes32 indexed proofSystemId, address indexed newAdapter, uint40 readyAt);
        event VerifierSwitchCancelled(bytes32 indexed proofSystemId, address indexed rejectedAdapter);
        // `Paused`/`Unpaused` share topic0 with the router's: filter by address.
        event Paused(address account);
        event Unpaused(address account);
        // The Registry's own upgrade timelock. `UpgradeExecuted` differs from the router's (it also
        // names the implementation), so its topic0 does too.
        event UpgradeProposed(bytes32 indexed opHash, uint48 readyAt);
        event UpgradeCancelled(bytes32 indexed opHash);
        event UpgradeExecuted(bytes32 indexed opHash, address indexed newImpl);

        function getAdapter(bytes32 proofSystemId) external view returns (AdapterEntry memory);
        function isBlacklisted(address verifier) external view returns (bool);
        function paused() external view returns (bool);
        // The pending verifier swap for a proof system; `(0, 0)` when none.
        function pendingReactivation(bytes32 proofSystemId) external view returns (address newAdapter, uint40 readyAt);
        // `(0, 0)` when nothing is pending.
        function pendingUpgrade() external view returns (bytes32 opHash, uint48 readyAt);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Verifier adapters and the native verifiers they wrap
    // ═══════════════════════════════════════════════════════════════════════════

    #[sol(rpc)]
    #[derive(Debug)]
    interface IVerifierAdapter {
        function nativeVerifier() external view returns (address);
        function name() external view returns (string);
        function version() external view returns (uint32);
    }

    // RISC Zero: the 4-byte prefix every seal for this verifier must carry.
    #[sol(rpc)]
    #[derive(Debug)]
    interface IRiscZeroSelectable {
        function SELECTOR() external view returns (bytes4);
    }

    // SP1: `VERIFIER_HASH()[0:4]` is the seal prefix; the whole hash names the circuit version.
    #[sol(rpc)]
    #[derive(Debug)]
    interface ISP1NativeVerifier {
        function VERIFIER_HASH() external pure returns (bytes32);
        function VERSION() external pure returns (string);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // IERC20
    // ═══════════════════════════════════════════════════════════════════════════

    #[sol(rpc)]
    #[derive(Debug)]
    interface IERC20 {
        function balanceOf(address account) external view returns (uint256);
        function allowance(address owner, address spender) external view returns (uint256);
        function approve(address spender, uint256 amount) external returns (bool);
        function transfer(address to, uint256 amount) external returns (bool);
        function transferFrom(address from, address to, uint256 amount) external returns (bool);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ITestnetToken — `mint` exists on the 743111 tHEMI but is `onlyOwner` (the token is
    // owner-minted); a prover's call reverts `OwnableUnauthorizedAccount`.
    // ═══════════════════════════════════════════════════════════════════════════

    #[sol(rpc)]
    #[derive(Debug)]
    interface ITestnetToken {
        function mint(address to, uint256 amount) external;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ProgramRegistry (advisory ELF/program metadata — registering a program is optional)
    // ═══════════════════════════════════════════════════════════════════════════

    #[derive(Debug)]
    struct StorageURI {
        uint8 storageType;   // 0=IPFS, 1=Arweave, 2=HTTP, 3=Custom
        string uri;
        bytes32 contentHash; // keccak256 of binary (bytes32(0) = not provided)
    }

    #[derive(Debug)]
    struct ResourceEstimate {
        uint64 estimatedCycles;
        uint64 peakMemoryBytes;
        uint32 estimatedWallTimeS;
    }

    #[derive(Debug)]
    struct ProgramVersion {
        bytes32 programId;
        bytes32 proofSystemId;
        bytes32 familyId;
        address registrant;
        uint40 registeredAt;
        uint8 status;             // 0=Active, 1=Deprecated, 2=Revoked
        bytes32 successorProgramId;
        ResourceEstimate resources;
        string name;
    }

    #[sol(rpc)]
    #[derive(Debug)]
    interface IProgramRegistry {
        function getProgram(bytes32 programId) external view returns (ProgramVersion memory);
        function getStorageURIs(bytes32 programId) external view returns (StorageURI[] memory);
        function isRegistered(bytes32 programId) external view returns (bool);
        function getBuildHashes(bytes32 programId) external view returns (bytes32 sourceCodeHash, bytes32 elfHash);
        function getResourceEstimate(bytes32 programId) external view returns (ResourceEstimate memory);
        function getIOSchema(bytes32 programId, uint8 schemaKind) external view returns (bytes schema);
        function registerProgram(
            bytes32 programId,
            bytes32 proofSystemId,
            bytes32 familyId,
            ResourceEstimate calldata resources,
            string calldata name,
            string calldata description,
            string calldata inputSchemaURI,
            StorageURI[] calldata initialURIs
        ) external;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // GasPriceOracle — the OP Stack L2 predeploy at 0x420000000000000000000000000000000000000F
    // (GAS_PRICE_ORACLE below). Hemi runs it at version 1.4.0 with Fjord active (`isFjord()`), so
    // `getL1GasUsed(unsignedTx)` is `max(100, -42.5856 + 0.8365 x (FastLZ(unsignedTx) + 68)) x 16`:
    // divided by 16, the estimated DA size the sequencer's per-transaction DA cap compares (the
    // same figure as a mined receipt's `l1GasUsed / 16`). Not part of the vendored HemiProve ABIs;
    // the selectors are pinned by `tests` below.
    // ═══════════════════════════════════════════════════════════════════════════

    #[sol(rpc)]
    #[derive(Debug)]
    interface IGasPriceOracle {
        function getL1GasUsed(bytes memory _data) external view returns (uint256);
        function getL1Fee(bytes memory _data) external view returns (uint256);
        function getL1FeeUpperBound(uint256 _unsignedTxSize) external view returns (uint256);
        function isFjord() external view returns (bool);
        function isEcotone() external view returns (bool);
        function l1BaseFee() external view returns (uint256);
        function baseFeeScalar() external view returns (uint32);
        function blobBaseFeeScalar() external view returns (uint32);
        function version() external view returns (string);
    }
}

/// The OP Stack `GasPriceOracle` predeploy (present on both Hemi chains).
pub const GAS_PRICE_ORACLE: alloy::primitives::Address =
    alloy::primitives::address!("420000000000000000000000000000000000000F");

/// The router's raw `jobs(jobId)` record (27 outputs, in ABI order). Decoded from the 27-word return
/// by [`JobRecord::from_words`], which REJECTS a word whose value does not fit its declared type —
/// so a layout drift fails loudly instead of yielding shifted values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JobRecord {
    pub caller: alloy::primitives::Address,
    pub status: u8,
    pub reopen_count: u8,
    pub job_index: u64,
    pub descriptor_hash: alloy::primitives::B256,
    pub deposited_amount: u128,
    pub bonus_amount: u128,
    /// RAW lock deadline (not pause-credited). Schedule from `getJobStatusView().lockDeadline`.
    pub lock_deadline: u64,
    pub prover: alloy::primitives::Address,
    pub locked_collateral: u128,
    pub ramp_up_start: u64,
    pub elapsed_at_lock: u64,
    pub settled_price: u128,
    pub callback_gas_limit: u32,
    pub operator_rejections: u8,
    pub min_price: u128,
    pub max_price: u128,
    pub ramp_up_period: u64,
    pub curve_type: u8,
    pub fulfillment_timeout: u64,
    pub lock_collateral_bps: u128,
    pub speed_premium: u128,
    pub claiming_operator: alloy::primitives::Address,
    pub exclusivity_duration: u64,
    pub callback_rejections: u8,
    pub last_reopen_timestamp: u64,
    pub exclude_from_ewma: bool,
}

impl JobRecord {
    /// `(abi name, abi type)` of each output, in order — pinned against the ABI by a test.
    pub const LAYOUT: [(&'static str, &'static str); 27] = [
        ("caller", "address"),
        ("status", "uint8"),
        ("reopenCount", "uint8"),
        ("jobIndex", "uint48"),
        ("descriptorHash", "bytes32"),
        ("depositedAmount", "uint96"),
        ("bonusAmount", "uint96"),
        ("lockDeadline", "uint40"),
        ("prover", "address"),
        ("lockedCollateral", "uint96"),
        ("rampUpStart", "uint40"),
        ("elapsedAtLock", "uint40"),
        ("settledPrice", "uint96"),
        ("callbackGasLimit", "uint32"),
        ("operatorRejections", "uint8"),
        ("minPrice", "uint96"),
        ("maxPrice", "uint96"),
        ("rampUpPeriod", "uint40"),
        ("curveType", "uint8"),
        ("fulfillmentTimeout", "uint40"),
        ("lockCollateralBps", "uint96"),
        ("speedPremium", "uint96"),
        ("claimingOperator", "address"),
        ("exclusivityDuration", "uint40"),
        ("callbackRejections", "uint8"),
        ("lastReopenTimestamp", "uint40"),
        ("excludeFromEwma", "bool"),
    ];

    /// Decode the 27-word return, validating that every word fits its declared type.
    pub fn from_words(w: &[alloy::primitives::B256; 27]) -> Result<Self, String> {
        use alloy::primitives::{Address, U256};
        fn uint(w: &alloy::primitives::B256, bits: usize, field: &str) -> Result<U256, String> {
            let v = U256::from_be_bytes(w.0);
            if bits < 256 && v >> bits != U256::ZERO {
                return Err(format!("jobs(): {field} does not fit uint{bits} (layout drift?)"));
            }
            Ok(v)
        }
        fn addr(w: &alloy::primitives::B256, field: &str) -> Result<Address, String> {
            uint(w, 160, field)?;
            Ok(Address::from_slice(&w.0[12..]))
        }
        let u = |i: usize, bits: usize| -> Result<U256, String> { uint(&w[i], bits, Self::LAYOUT[i].0) };
        let to_u128 = |v: U256| -> u128 { v.to::<u128>() };
        let to_u64 = |v: U256| -> u64 { v.to::<u64>() };
        let flag = uint(&w[26], 1, "excludeFromEwma")?;
        Ok(Self {
            caller: addr(&w[0], "caller")?,
            status: u(1, 8)?.to::<u8>(),
            reopen_count: u(2, 8)?.to::<u8>(),
            job_index: to_u64(u(3, 48)?),
            descriptor_hash: w[4],
            deposited_amount: to_u128(u(5, 96)?),
            bonus_amount: to_u128(u(6, 96)?),
            lock_deadline: to_u64(u(7, 40)?),
            prover: addr(&w[8], "prover")?,
            locked_collateral: to_u128(u(9, 96)?),
            ramp_up_start: to_u64(u(10, 40)?),
            elapsed_at_lock: to_u64(u(11, 40)?),
            settled_price: to_u128(u(12, 96)?),
            callback_gas_limit: u(13, 32)?.to::<u32>(),
            operator_rejections: u(14, 8)?.to::<u8>(),
            min_price: to_u128(u(15, 96)?),
            max_price: to_u128(u(16, 96)?),
            ramp_up_period: to_u64(u(17, 40)?),
            curve_type: u(18, 8)?.to::<u8>(),
            fulfillment_timeout: to_u64(u(19, 40)?),
            lock_collateral_bps: to_u128(u(20, 96)?),
            speed_premium: to_u128(u(21, 96)?),
            claiming_operator: addr(&w[22], "claimingOperator")?,
            exclusivity_duration: to_u64(u(23, 40)?),
            callback_rejections: u(24, 8)?.to::<u8>(),
            last_reopen_timestamp: to_u64(u(25, 40)?),
            exclude_from_ewma: flag != U256::ZERO,
        })
    }
}

/// Pins every binding against the vendored 3bc441d ABI JSON (`hemiprove-abi/`). These compare the
/// CANONICAL SIGNATURES (inputs, and for views the full output tuple incl. struct member types in
/// order) — so a reordered, removed or added struct member fails here instead of decoding silently
/// shifted values at runtime, which is exactly how the July `JobStatusView` drifted unnoticed.
#[cfg(test)]
mod tests {
    use super::*;
    use alloy::json_abi::{Function, JsonAbi, Param};
    use alloy::primitives::B256;
    use alloy::sol_types::{SolCall, SolError, SolEvent};

    fn abi(name: &str) -> JsonAbi {
        let path = format!("{}/../../hemiprove-abi/{name}", env!("CARGO_MANIFEST_DIR"));
        let s = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        serde_json::from_str(&s).unwrap_or_else(|e| panic!("parse {path}: {e}"))
    }

    fn router() -> JsonAbi {
        abi("HemiProveRouter.abi.json")
    }

    /// Canonical type of a param, expanding tuples recursively (`(uint8,address,...)[]`).
    fn canon(p: &Param) -> String {
        if let Some(rest) = p.ty.strip_prefix("tuple") {
            let inner: Vec<String> = p.components.iter().map(canon).collect();
            format!("({}){rest}", inner.join(","))
        } else {
            p.ty.clone()
        }
    }

    fn only(abi: &JsonAbi, name: &str) -> Function {
        let fs = abi.function(name).unwrap_or_else(|| panic!("{name} missing from the ABI"));
        assert_eq!(fs.len(), 1, "{name} is overloaded in the ABI; pin it explicitly");
        fs[0].clone()
    }

    fn outputs(f: &Function) -> String {
        format!("({})", f.outputs.iter().map(canon).collect::<Vec<_>>().join(","))
    }

    /// Assert a sol! call's selector equals the ABI's, and (when given) that the ABI's canonical
    /// output tuple equals `want_out`.
    macro_rules! pin_call {
        ($abi:expr, $call:ty, $name:literal) => {{
            let f = only(&$abi, $name);
            assert_eq!(
                <$call as SolCall>::SELECTOR,
                f.selector().0,
                "{} selector drifted: binding {} vs ABI {}",
                $name,
                <$call as SolCall>::SIGNATURE,
                f.signature()
            );
            f
        }};
    }

    #[test]
    fn router_call_selectors_match_the_deployed_abi() {
        let r = router();
        pin_call!(r, IHemiProveCore::submitJobCall, "submitJob");
        pin_call!(r, IHemiProveCore::submitJobDefaultCall, "submitJobDefault");
        pin_call!(r, IHemiProveCore::submitJobSimpleCall, "submitJobSimple");
        pin_call!(r, IHemiProveCore::submitJobBatchCall, "submitJobBatch");
        pin_call!(r, IHemiProveCore::claimJobCall, "claimJob");
        pin_call!(r, IHemiProveCore::claimJobDelegatedCall, "claimJobDelegated");
        pin_call!(r, IHemiProveCore::claimJobBatchCall, "claimJobBatch");
        pin_call!(r, IHemiProveCore::topUpDepositCall, "topUpDeposit");
        pin_call!(r, IHemiProveCore::withdrawCall, "withdraw");
        pin_call!(r, IHemiProveCore::jobIndexCall, "jobIndex");
        pin_call!(r, IHemiProveFulfill::fulfillJobCall, "fulfillJob");
        pin_call!(r, IHemiProveFulfill::fulfillJobHashedCall, "fulfillJobHashed");
        pin_call!(r, IHemiProveFulfill::releaseJobCall, "releaseJob");
        pin_call!(r, IHemiProveFulfill::graceReleaseCall, "graceRelease");
        pin_call!(r, IHemiProveFulfill::gracePauseReleaseCall, "gracePauseRelease");
        pin_call!(r, IHemiProveFulfill::slashAndReopenCall, "slashAndReopen");
        pin_call!(r, IHemiProveFulfill::slashAndClaimCall, "slashAndClaim");
        pin_call!(r, IHemiProveFulfill::cancelJobCall, "cancelJob");
        pin_call!(r, IHemiProveAux::MIN_COLLATERAL_AMOUNTCall, "MIN_COLLATERAL_AMOUNT");
        pin_call!(r, IHemiProveAux::getCurrentPriceCall, "getCurrentPrice");
        pin_call!(r, IHemiProveAux::getJobExtrasCall, "getJobExtras");
        pin_call!(r, IHemiProveAux::getJobSnapshotsCall, "getJobSnapshots");
        pin_call!(r, IHemiProveAux::getPremiumCapCall, "getPremiumCap");
        pin_call!(r, IHemiProveAux::previewSpeedBonusCall, "previewSpeedBonus");
        pin_call!(r, IHemiProveAux::getProofNonceCall, "getProofNonce");
        pin_call!(r, IHemiProveAux::bidConfigsCall, "bidConfigs");
        pin_call!(r, IHemiProveAux::jobAssignedProversCall, "jobAssignedProvers");
        pin_call!(r, IHemiProveAux::jobProofSystemsCall, "jobProofSystems");
        pin_call!(r, IHemiProveAux::isPendingSettlementCall, "isPendingSettlement");
        pin_call!(r, IHemiProveAux::pausedCall, "paused");
        pin_call!(r, IHemiProveAux::getUnionClockCall, "getUnionClock");
        pin_call!(r, IHemiProveAux::getKeyClockCall, "getKeyClock");
        pin_call!(r, IHemiProveAux::stakingCall, "staking");
        pin_call!(r, IHemiProveAux::registryCall, "registry");
        pin_call!(r, IHemiProveAux::hemiTokenCall, "hemiToken");
        pin_call!(r, IHemiProveAux::getVerifiedResultCall, "getVerifiedResult");
        pin_call!(r, IHemiProveAux::suggestPriceRangeCall, "suggestPriceRange");
        pin_call!(r, IHemiProveAux::submitBidCall, "submitBid");
        pin_call!(r, IHemiProveAux::settleBidCall, "settleBid");
    }

    #[test]
    fn router_view_outputs_match_the_deployed_abi_member_for_member() {
        let r = router();
        // JobStatusView: the struct that silently drifted. Compare the full ordered member types.
        let f = pin_call!(r, IHemiProveAux::getJobStatusViewCall, "getJobStatusView");
        assert_eq!(
            outputs(&f),
            "((uint8,address,address,uint96,uint96,uint96,uint96,uint96,uint40,uint40,uint40,uint40,\
             uint8,uint8,bytes32,bytes32,address,uint96,uint40,uint64,uint8,uint40))"
        );
        // ...and the binding's own member names line up with the ABI's, in order.
        let abi_names: Vec<&str> =
            f.outputs[0].components.iter().map(|c| c.name.as_str()).collect();
        let bound = <JobStatusView as alloy::sol_types::SolStruct>::eip712_root_type();
        let bound_names: Vec<&str> = bound
            .trim_start_matches("JobStatusView(")
            .trim_end_matches(')')
            .split(',')
            .map(|m| m.rsplit(' ').next().unwrap())
            .collect();
        assert_eq!(bound_names, abi_names, "JobStatusView member order drifted");

        let f = pin_call!(r, IHemiProveAux::jobsCall, "jobs");
        let abi_layout: Vec<(String, String)> =
            f.outputs.iter().map(|o| (o.name.clone(), canon(o))).collect();
        let bound_layout: Vec<(String, String)> = JobRecord::LAYOUT
            .iter()
            .map(|(n, t)| (n.to_string(), t.to_string()))
            .collect();
        assert_eq!(abi_layout, bound_layout, "jobs() output layout drifted from JobRecord::LAYOUT");
        // Every output is static, so the return is exactly 27 words — the bytes32[27] binding.
        assert!(f.outputs.iter().all(|o| !o.ty.starts_with("bytes") || o.ty == "bytes32"));

        let f = pin_call!(r, IHemiProveAux::getBidStateCall, "getBidState");
        assert_eq!(outputs(&f), "((address,address,uint96,uint40,uint40,uint96,uint40))");
        let f = pin_call!(r, IHemiProveAux::getProofNonceCall, "getProofNonce");
        assert_eq!(outputs(&f), "(uint256,uint32[4])");
        let f = pin_call!(r, IHemiProveAux::getJobExtrasCall, "getJobExtras");
        assert_eq!(outputs(&f), "(uint256,uint40,bool)");
        let f = pin_call!(r, IHemiProveAux::getJobSnapshotsCall, "getJobSnapshots");
        assert_eq!(outputs(&f), "(uint256,uint256,uint256)");
        let f = pin_call!(r, IHemiProveCore::claimJobCall, "claimJob");
        assert_eq!(outputs(&f), "(uint96)");
    }

    #[test]
    fn job_record_decodes_in_order_and_rejects_out_of_range_words() {
        let mut w = [B256::ZERO; 27];
        let set = |w: &mut [B256; 27], i: usize, v: u128| {
            w[i] = B256::from(alloy::primitives::U256::from(v));
        };
        let prover = alloy::primitives::Address::repeat_byte(0x33);
        let mut pw = [0u8; 32];
        pw[12..].copy_from_slice(prover.as_slice());
        w[8] = B256::from(pw);
        set(&mut w, 1, 1); // Locked
        set(&mut w, 7, 1_800_000_000);
        set(&mut w, 9, 150);
        set(&mut w, 19, 300);
        let r = JobRecord::from_words(&w).expect("valid record");
        assert_eq!(r.status, 1);
        assert_eq!(r.prover, prover);
        assert_eq!(r.lock_deadline, 1_800_000_000);
        assert_eq!(r.locked_collateral, 150);
        assert_eq!(r.fulfillment_timeout, 300);
        // A shifted layout puts a large value where a uint8 is declared: must be refused, not
        // silently truncated.
        let mut bad = w;
        set(&mut bad, 1, 1_800_000_000);
        assert!(JobRecord::from_words(&bad).is_err());
        // ...and an address word with dirty high bytes too.
        let mut bad = w;
        bad[8] = B256::repeat_byte(0xff);
        assert!(JobRecord::from_words(&bad).is_err());
    }

    #[test]
    fn router_event_topics_match_the_deployed_abi() {
        let r = router();
        let topic = |name: &str| -> B256 {
            let es = r.event(name).unwrap_or_else(|| panic!("event {name} missing"));
            assert_eq!(es.len(), 1);
            es[0].selector()
        };
        assert_eq!(IHemiProveCore::JobSubmitted::SIGNATURE_HASH, topic("JobSubmitted"));
        assert_eq!(IHemiProveCore::JobClaimed::SIGNATURE_HASH, topic("JobClaimed"));
        assert_eq!(IHemiProveCore::PayoutCredited::SIGNATURE_HASH, topic("PayoutCredited"));
        assert_eq!(IHemiProveFulfill::JobFulfilled::SIGNATURE_HASH, topic("JobFulfilled"));
        assert_eq!(IHemiProveFulfill::JobReleased::SIGNATURE_HASH, topic("JobReleased"));
        assert_eq!(IHemiProveFulfill::JobReopened::SIGNATURE_HASH, topic("JobReopened"));
        assert_eq!(IHemiProveFulfill::JobCancelled::SIGNATURE_HASH, topic("JobCancelled"));
        assert_eq!(IHemiProveFulfill::GracePauseReleased::SIGNATURE_HASH, topic("GracePauseReleased"));
        assert_eq!(IHemiProveFulfill::GraceReleased::SIGNATURE_HASH, topic("GraceReleased"));
        assert_eq!(IHemiProveFulfill::DeadlineExtended::SIGNATURE_HASH, topic("DeadlineExtended"));
        assert_eq!(IHemiProveAux::Paused::SIGNATURE_HASH, topic("Paused"));
        assert_eq!(IHemiProveAux::Unpaused::SIGNATURE_HASH, topic("Unpaused"));
        assert_eq!(
            IHemiProveAux::BidSubmitted::SIGNATURE_HASH,
            topic("BidSubmitted")
        );
        assert_eq!(
            IHemiProveRouterGov::UpgradeProposed::SIGNATURE_HASH,
            topic("UpgradeProposed")
        );
        assert_eq!(
            IHemiProveRouterGov::UpgradeCancelled::SIGNATURE_HASH,
            topic("UpgradeCancelled")
        );
        assert_eq!(
            IHemiProveRouterGov::UpgradeExecuted::SIGNATURE_HASH,
            topic("UpgradeExecuted")
        );
        let f = pin_call!(r, IHemiProveRouterGov::pendingUpgradeCall, "pendingUpgrade");
        assert_eq!(outputs(&f), "(bytes32,uint48)");
        // Handoff Appendix C values, as a second, independent anchor.
        assert_eq!(
            format!("{:x}", IHemiProveCore::JobSubmitted::SIGNATURE_HASH),
            "83de06bf8caab89fc798ea0f0b6a2bfb28a5c5dfe80823a65647257f79e056c4"
        );
        assert_eq!(
            format!("{:x}", IHemiProveFulfill::JobCancelled::SIGNATURE_HASH),
            "a96b38c2858070b5eb59b3be21c9261ebf35b64c358634f372d7e2b1e17b4e88"
        );
    }

    /// The Registry events the governance watcher decodes (verifier swaps, adapter disables, pauses,
    /// upgrades), pinned against the deployed Registry ABI. `Paused`/`Unpaused` and the upgrade events
    /// must equal the router's where the signatures agree, since the watcher tells them apart by
    /// address only.
    #[test]
    fn registry_event_topics_match_the_deployed_abi() {
        let g = abi("HemiProveRegistry.abi.json");
        let topic = |name: &str| -> B256 {
            let es = g
                .event(name)
                .unwrap_or_else(|| panic!("event {name} missing"));
            assert_eq!(es.len(), 1);
            es[0].selector()
        };
        assert_eq!(
            IHemiProveRegistry::AdapterDisabledEvent::SIGNATURE_HASH,
            topic("AdapterDisabledEvent")
        );
        assert_eq!(
            IHemiProveRegistry::AdapterReactivated::SIGNATURE_HASH,
            topic("AdapterReactivated")
        );
        assert_eq!(
            IHemiProveRegistry::AdapterRegistered::SIGNATURE_HASH,
            topic("AdapterRegistered")
        );
        assert_eq!(
            IHemiProveRegistry::VerifierSwitchProposed::SIGNATURE_HASH,
            topic("VerifierSwitchProposed")
        );
        assert_eq!(
            IHemiProveRegistry::VerifierSwitchCancelled::SIGNATURE_HASH,
            topic("VerifierSwitchCancelled")
        );
        assert_eq!(IHemiProveRegistry::Paused::SIGNATURE_HASH, topic("Paused"));
        assert_eq!(
            IHemiProveRegistry::Unpaused::SIGNATURE_HASH,
            topic("Unpaused")
        );
        assert_eq!(
            IHemiProveRegistry::UpgradeProposed::SIGNATURE_HASH,
            topic("UpgradeProposed")
        );
        assert_eq!(
            IHemiProveRegistry::UpgradeCancelled::SIGNATURE_HASH,
            topic("UpgradeCancelled")
        );
        assert_eq!(
            IHemiProveRegistry::UpgradeExecuted::SIGNATURE_HASH,
            topic("UpgradeExecuted")
        );
        // Shared with the router's (same signature) — or not (UpgradeExecuted names the impl here).
        assert_eq!(
            IHemiProveRegistry::Paused::SIGNATURE_HASH,
            IHemiProveAux::Paused::SIGNATURE_HASH
        );
        assert_eq!(
            IHemiProveRegistry::Unpaused::SIGNATURE_HASH,
            IHemiProveAux::Unpaused::SIGNATURE_HASH
        );
        assert_eq!(
            IHemiProveRegistry::UpgradeProposed::SIGNATURE_HASH,
            IHemiProveRouterGov::UpgradeProposed::SIGNATURE_HASH
        );
        assert_eq!(
            IHemiProveRegistry::UpgradeCancelled::SIGNATURE_HASH,
            IHemiProveRouterGov::UpgradeCancelled::SIGNATURE_HASH
        );
        assert_ne!(
            IHemiProveRegistry::UpgradeExecuted::SIGNATURE_HASH,
            IHemiProveRouterGov::UpgradeExecuted::SIGNATURE_HASH
        );
    }

    #[test]
    fn every_declared_error_exists_in_the_deployed_abis_with_the_same_selector() {
        let mut deployed = std::collections::HashMap::new();
        for file in ["HemiProveRouter.abi.json", "HemiProveStaking.abi.json", "HemiProveRegistry.abi.json"]
        {
            for e in abi(file).errors() {
                deployed.insert(e.signature(), e.selector().0);
            }
        }
        // OpenZeppelin's Ownable error lives on the token, not in these ABIs.
        let token_only = ["OwnableUnauthorizedAccount(address)"];
        for sig in IHemiProveErrors::IHemiProveErrorsErrors::SIGNATURES {
            if token_only.contains(sig) {
                continue;
            }
            let sel = deployed
                .get(*sig)
                .unwrap_or_else(|| panic!("error {sig} is not in the deployed ABIs"));
            assert_eq!(
                alloy::primitives::keccak256(sig.as_bytes())[..4],
                sel[..],
                "selector for {sig}"
            );
        }
        // Spot-check selectors quoted in the handoff (§9).
        assert_eq!(IHemiProveErrors::ClaimBelowFloor::SELECTOR, [0xc8, 0xce, 0xa6, 0x2a]);
        assert_eq!(IHemiProveErrors::VerifierCallFailed::SELECTOR, [0xbe, 0xee, 0x77, 0xb7]);
        assert_eq!(IHemiProveErrors::JournalMismatch::SELECTOR, [0x91, 0xd0, 0x7f, 0x1e]);
        assert_eq!(IHemiProveErrors::EnforcedPause::SELECTOR, [0xd9, 0x3c, 0x06, 0x65]);
    }

    /// The GasPriceOracle predeploy has no vendored ABI: pin its selectors to the OP Stack
    /// signatures (and `cast sig`'s values), and fulfillJobHashed's to its canonical signature —
    /// the struct's member order is what `fulfill_job_hashed` encodes.
    #[test]
    fn gas_price_oracle_and_fulfill_job_hashed_selectors() {
        assert_eq!(IGasPriceOracle::getL1GasUsedCall::SELECTOR, [0xde, 0x26, 0xc4, 0xa1]);
        assert_eq!(IGasPriceOracle::getL1FeeCall::SELECTOR, [0x49, 0x94, 0x8e, 0x0e]);
        assert_eq!(IGasPriceOracle::getL1FeeUpperBoundCall::SELECTOR, [0xf1, 0xc7, 0xa5, 0x8b]);
        assert_eq!(IGasPriceOracle::isFjordCall::SELECTOR, [0x96, 0x0e, 0x3a, 0x23]);
        assert_eq!(IGasPriceOracle::isEcotoneCall::SELECTOR, [0x4e, 0xf6, 0xe2, 0x24]);
        assert_eq!(IGasPriceOracle::l1BaseFeeCall::SELECTOR, [0x51, 0x9b, 0x4b, 0xd3]);
        assert_eq!(IGasPriceOracle::baseFeeScalarCall::SELECTOR, [0xc5, 0x98, 0x59, 0x18]);
        assert_eq!(IGasPriceOracle::blobBaseFeeScalarCall::SELECTOR, [0x68, 0xd5, 0xdc, 0xa6]);
        assert_eq!(IGasPriceOracle::versionCall::SELECTOR, [0x54, 0xfd, 0x4d, 0x50]);
        assert_eq!(
            format!("{GAS_PRICE_ORACLE}"),
            "0x420000000000000000000000000000000000000F"
        );
        assert_eq!(
            IHemiProveFulfill::fulfillJobHashedCall::SIGNATURE,
            "fulfillJobHashed(bytes32,(bytes32,bytes32,address,address,bytes32,bytes32,bytes32,bytes32),\
             bytes,bytes,bytes,bytes)"
        );
        assert_eq!(IHemiProveFulfill::fulfillJobHashedCall::SELECTOR, [0x80, 0xf7, 0x65, 0xf2]);
        // ...and the member names line up with the ABI's HashedDescriptor, in order.
        let f = only(&router(), "fulfillJobHashed");
        let abi_names: Vec<&str> = f.inputs[1].components.iter().map(|c| c.name.as_str()).collect();
        let bound = <HashedDescriptor as alloy::sol_types::SolStruct>::eip712_root_type();
        let bound_names: Vec<&str> = bound
            .trim_start_matches("HashedDescriptor(")
            .trim_end_matches(')')
            .split(',')
            .map(|m| m.rsplit(' ').next().unwrap())
            .collect();
        assert_eq!(bound_names, abi_names, "HashedDescriptor member order drifted");
    }

    #[test]
    fn staking_registry_and_program_registry_match_the_deployed_abis() {
        let s = abi("HemiProveStaking.abi.json");
        pin_call!(s, IHemiProveStaking::stakeCall, "stake");
        pin_call!(s, IHemiProveStaking::requestUnstakeCall, "requestUnstake");
        pin_call!(s, IHemiProveStaking::withdrawUnstakedCall, "withdrawUnstaked");
        pin_call!(s, IHemiProveStaking::cancelUnstakeCall, "cancelUnstake");
        pin_call!(s, IHemiProveStaking::getAvailableCollateralCall, "getAvailableCollateral");
        pin_call!(s, IHemiProveStaking::hemiTokenCall, "hemiToken");
        let f = pin_call!(s, IHemiProveStaking::getProverStakeCall, "getProverStake");
        assert_eq!(outputs(&f), "((uint128,uint128,uint128,uint40,uint40))");
        let f = pin_call!(s, IHemiProveStaking::getProverStatsCall, "getProverStats");
        assert_eq!(outputs(&f), "((uint64,uint64,uint64,uint96,uint40,uint40))");

        let g = abi("HemiProveRegistry.abi.json");
        let f = pin_call!(g, IHemiProveRegistry::getAdapterCall, "getAdapter");
        assert_eq!(outputs(&f), "((address,uint8,uint40,bytes32,uint96,uint128,uint16,uint8))");
        pin_call!(g, IHemiProveRegistry::isBlacklistedCall, "isBlacklisted");
        pin_call!(g, IHemiProveRegistry::pausedCall, "paused");
        let f = pin_call!(
            g,
            IHemiProveRegistry::pendingReactivationCall,
            "pendingReactivation"
        );
        assert_eq!(outputs(&f), "(address,uint40)");
        let f = pin_call!(g, IHemiProveRegistry::pendingUpgradeCall, "pendingUpgrade");
        assert_eq!(outputs(&f), "(bytes32,uint48)");

        let p = abi("ProgramRegistry.abi.json");
        let f = pin_call!(p, IProgramRegistry::getProgramCall, "getProgram");
        assert_eq!(
            outputs(&f),
            "((bytes32,bytes32,bytes32,address,uint40,uint8,bytes32,(uint64,uint64,uint32),string))"
        );
        let f = pin_call!(p, IProgramRegistry::getStorageURIsCall, "getStorageURIs");
        assert_eq!(outputs(&f), "((uint8,string,bytes32)[])");
        let f = pin_call!(p, IProgramRegistry::getBuildHashesCall, "getBuildHashes");
        assert_eq!(outputs(&f), "(bytes32,bytes32)");
        pin_call!(p, IProgramRegistry::isRegisteredCall, "isRegistered");
        pin_call!(p, IProgramRegistry::registerProgramCall, "registerProgram");

        for adapter in [
            "RiscZeroGroth16VerifierAdapter.abi.json",
            "SP1Groth16VerifierAdapter.abi.json",
            "SP1PlonkVerifierAdapter.abi.json",
        ] {
            let a = abi(adapter);
            pin_call!(a, IVerifierAdapter::nativeVerifierCall, "nativeVerifier");
            pin_call!(a, IVerifierAdapter::nameCall, "name");
            pin_call!(a, IVerifierAdapter::versionCall, "version");
        }
    }
}
