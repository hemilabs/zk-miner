use alloy::sol;

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
        // [Phase 2 predicate, 2026-07-10] Optional outcome commitment. When
        // non-zero, after the verifier accepts the router requires
        //   keccak256(abi.encode(JOURNAL_PREDICATE_DOMAIN_V1, proofSystemId,
        //   programId, publicValues)) == expectedJournalHash
        // else it reverts JournalMismatch BEFORE any payment. Zero = opt-out.
        // This is the 9th descriptor-hash slot (see zkminer-chain descriptor.rs).
        bytes32 expectedJournalHash;
    }

    #[derive(Debug, PartialEq, Eq)]
    struct HashedDescriptor {
        bytes32 programId;
        bytes32 proofSystemId;
        address callbackContract;
        address assignedProver;
        bytes32 tag;
        bytes32 inputDataHash;
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
        bool strictCallbackMode;
    }

    #[derive(Debug)]
    struct ProverStake {
        uint128 totalStaked;
        uint128 lockedCollateral;
        uint128 unstakeAmount;
        uint40 unstakeRequestTime;
        // [FIX-V1A3, 2026-07-08] Renamed from depositTimestamp AND semantics
        // changed: this now holds block.number (a BLOCK NUMBER, not a unix
        // timestamp). Claim eligibility is block.number > depositBlock (the
        // 1h MIN_STAKING_AGE gate was removed).
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

    #[derive(Debug)]
    struct JobStatusView {
        uint8 status;
        address caller;
        address prover;
        uint96 currentAuctionPrice;
        uint96 depositedAmount;
        uint96 bonusAmount;
        uint96 totalProverReward;
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
        // Added in HemiProve v2026-07-07 (hemiprove-abi/HemiProveCore.abi.json).
        // Must match the on-chain CycleConfig or submitJob calldata decoding
        // (JobDescriptor reconstruction in zkminer-chain/descriptor.rs) misaligns.
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
        event JobClaimed(
            bytes32 indexed jobId, address indexed prover, address indexed operator,
            uint96 settledPrice, uint96 bonusAmount, uint40 lockDeadline
        );

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
            address callbackContract
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

        function claimJob(bytes32 jobId) external;
        function claimJobDelegated(bytes32 jobId, address prover) external;
        // Batch-lock up to MAX_BATCH_SIZE (10) jobs in one tx. Partial-completion:
        // per-job failures (lost race, adapter disabled, insufficient collateral)
        // are isolated via a `_claimJobExternal` self-call and reported in the
        // returned bool[]; the outer tx still succeeds. We reconcile which actually
        // locked via getJobStatusView rather than the (receipt-invisible) return.
        function claimJobBatch(bytes32[] jobIds) external returns (bool[] results);
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
        event JobCancelled(bytes32 indexed jobId, address indexed caller, uint256 refundAmount, bool bonusIncluded);

        function fulfillJob(
            bytes32 jobId,
            JobDescriptor calldata descriptor,
            bytes calldata publicValues,
            bytes calldata proofBytes
        ) external;

        function fulfillJobHashed(
            bytes32 jobId,
            HashedDescriptor calldata hashedDescriptor,
            bytes calldata callbackExtraData,
            bytes calldata extraVerifierData,
            bytes calldata publicValues,
            bytes calldata proofBytes
        ) external;

        function claimAndFulfillJob(
            bytes32 jobId,
            JobDescriptor calldata descriptor,
            bytes calldata publicValues,
            bytes calldata proofBytes,
            address prover,
            bytes calldata proverSignature,
            uint256 deadline
        ) external;

        function submitAndFulfillJob(
            JobDescriptor calldata descriptor,
            AuctionConfig calldata config,
            bytes calldata publicValues,
            bytes calldata proofBytes,
            address prover,
            bytes calldata proverSignature,
            uint256 deadline
        ) external returns (bytes32 jobId);

        function releaseJob(bytes32 jobId) external;
        function slashAndReopen(bytes32 jobId) external;
        function slashAndClaim(bytes32 jobId) external;
        function cancelJob(bytes32 jobId) external;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // HemiProveAux — Views, Bidding, Governance
    // ═══════════════════════════════════════════════════════════════════════════

    #[sol(rpc)]
    #[derive(Debug)]
    interface IHemiProveAux {
        // Governance-set per-job collateral floor (Constants.MIN_COLLATERAL_AMOUNT);
        // the on-chain claim floors computeCollateral() with this. Distinct from an
        // adapter's minStake (prover-eligibility total-stake threshold).
        function MIN_COLLATERAL_AMOUNT() external view returns (uint256);
        function getCurrentPrice(bytes32 jobId) external view returns (uint96);
        function getJobStatusView(bytes32 jobId) external view returns (JobStatusView memory);
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

        function stake(address prover, uint128 amount) external;
        function requestUnstake(uint128 amount) external;
        function withdrawUnstaked() external;
        function cancelUnstake() external;
        function getProverStake(address prover) external view returns (ProverStake memory);
        function getAvailableCollateral(address prover) external view returns (uint128);
        function getProverStats(address prover) external view returns (ProverStats memory);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // HemiProveRegistry
    // ═══════════════════════════════════════════════════════════════════════════

    #[sol(rpc)]
    #[derive(Debug)]
    interface IHemiProveRegistry {
        function getAdapter(bytes32 proofSystemId) external view returns (AdapterEntry memory);
        function isBlacklisted(address verifier) external view returns (bool);
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
    // ITestnetToken — extends IERC20 with public mint (testnet only)
    // ═══════════════════════════════════════════════════════════════════════════

    #[sol(rpc)]
    #[derive(Debug)]
    interface ITestnetToken {
        function mint(address to, uint256 amount) external;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ProgramRegistry (advisory ELF/program metadata)
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
}
