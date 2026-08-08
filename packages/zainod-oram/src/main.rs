//! Non-published one-shot tools for Zaino ORAM research.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(feature = "private-service")]
use blake2::{Blake2s256, Digest};
use std::{
    error::Error,
    fmt,
    future::Future,
    num::{NonZeroU32, NonZeroUsize},
    ops::RangeInclusive,
    path::PathBuf,
    process::ExitCode,
};
#[cfg(feature = "private-service")]
use std::{
    net::SocketAddr,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
#[cfg(feature = "typed-qualification")]
use std::{num::NonZeroU64, time::Duration};

use clap::ValueEnum;
use clap::{Args, Parser, Subcommand};
use futures::{stream, StreamExt};
use zaino_common::Network;
#[cfg(feature = "typed-qualification")]
use zaino_oram::{
    derive_fixed_page_capacity_lower_bound, run_typed_worker_full_map_saturation,
    run_typed_worker_qualification, run_typed_worker_stress_qualification,
    run_typed_worker_target_load, TypedWorkerColdRebuildProfile, TypedWorkerColdRebuildReport,
    TypedWorkerColdRebuildSession, TypedWorkerFullMapSaturationProfile, TypedWorkerStressProfile,
    TypedWorkerTargetLoadProfile,
};
#[cfg(feature = "private-service")]
use zaino_oram::{
    mainnet_private_query_runtime, FinalizedProjectionBuilder, MainnetPrivateQueryRuntime,
    PrivateNetwork, PrivateProjectionShape, PrivateRuntimeDeployment, PrivateRuntimeKeys,
    PRIVATE_MAINNET_ENVELOPE_BYTES,
};
use zaino_oram::{MainnetCorpusMeasurement, MainnetCorpusScanner, MainnetSizingModel};
use zaino_oram::{
    SourceBoundHybridSizingProfile, SourceBoundHybridSizingReport, SourceBoundHybridSizingSession,
};
use zaino_oram::{
    SourceBoundInsertionBudgetProfile, SourceBoundInsertionBudgetReport,
    SourceBoundInsertionBudgetSession,
};
#[cfg(feature = "private-service")]
use zaino_state::ValidatorConnector;
use zaino_state::{
    chain_index::NonFinalizedSnapshot, ChainIndex, ChainIndexSnapshot, Height, IndexedBlock,
    NodeBackedIndexerService, NodeBackedIndexerServiceConfig, ZcashService,
};
use zainodlib::{
    cli::default_config_path,
    config::{load_config, BackendType},
};

#[cfg(feature = "typed-qualification")]
use crate::cold_rebuild_artifact::publish_cold_rebuild;
use crate::corpus_artifact::{
    load_capture, load_sizing, publish_capture, publish_sizing, BackendKind, CaptureProvenance,
    PreverifiedSourceSnapshotV1, SelectionMode, SnapshotMode, ValidatedCapture, ValidatedSizing,
};
#[cfg(feature = "typed-qualification")]
use crate::execution_identity::{
    create_release_receipt, verify_release_receipt, ReleaseReceiptInputs,
};
#[cfg(feature = "typed-qualification")]
use crate::full_map_saturation_artifact::publish_full_map_saturation;
#[cfg(feature = "typed-qualification")]
use crate::gate2::{
    create_timing_manifest, inspect_timing_attempt_ledger, inspect_timing_manifest,
    run_timing_attempt, seal_dangling_timing_attempt, verify_timing_manifest,
    TimingAttemptInspectInputs, TimingAttemptOutcome, TimingAttemptRunInputs,
    TimingAttemptSealInputs, TimingAttemptSummary, TimingAttemptTerminalState,
    TimingManifestCreateInputs, TimingManifestInspectInputs, TimingManifestVerifyInputs,
};
#[cfg(feature = "typed-qualification")]
use crate::hybrid_sizing_artifact::load_hybrid_sizing;
use crate::hybrid_sizing_artifact::publish_hybrid_sizing;
use crate::insertion_bound_artifact::publish_insertion_bound;
#[cfg(feature = "typed-qualification")]
use crate::qualification_artifact::publish_qualification;
#[cfg(feature = "typed-qualification")]
use crate::stress_qualification_artifact::publish_stress_qualification;
#[cfg(feature = "typed-qualification")]
use crate::target_load_artifact::publish_target_load;

#[cfg(feature = "typed-qualification")]
mod cold_rebuild_artifact;
mod corpus_artifact;
#[cfg(feature = "typed-qualification")]
mod execution_identity;
#[cfg(feature = "typed-qualification")]
mod full_map_saturation_artifact;
#[cfg(feature = "typed-qualification")]
mod gate2;
mod hybrid_sizing_artifact;
mod insertion_bound_artifact;
#[cfg(feature = "private-service")]
mod private_proto;
#[cfg(feature = "private-service")]
mod private_service;
#[cfg(feature = "private-service")]
use crate::private_service::PrivateQueryListener;
#[cfg(feature = "typed-qualification")]
mod qualification_artifact;
#[cfg(feature = "typed-qualification")]
mod stress_qualification_artifact;
#[cfg(feature = "typed-qualification")]
mod target_load_artifact;
#[cfg(feature = "typed-qualification")]
mod timing_contract;
#[cfg(feature = "typed-qualification")]
mod timing_driver;

type RunnerResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

const MAX_CAPTURE_FETCH_CONCURRENCY: usize = 32;

#[derive(Debug, Parser)]
#[command(
    name = "zainod-oram",
    version,
    about = "Non-published Zaino ORAM research tools"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Capture or inspect ORAM corpus evidence.
    Corpus(CorpusCommand),
    /// Create or verify a self-reported local-integrity receipt without a listener.
    #[cfg(feature = "typed-qualification")]
    Release(ReleaseCommand),
    /// Run source-bound or typed-worker qualification procedures without a listener.
    Qualification(QualificationCommand),
    /// Serve the private ORAM query surface over a bound gRPC listener.
    #[cfg(feature = "private-service")]
    Private(PrivateCommand),
}

#[cfg(feature = "private-service")]
#[derive(Debug, Args)]
struct PrivateCommand {
    #[command(subcommand)]
    command: PrivateSubcommand,
}

#[cfg(feature = "private-service")]
#[derive(Debug, Subcommand)]
enum PrivateSubcommand {
    /// Rebuild a finalized projection from the node, then serve private queries.
    Serve(PrivateServeArgs),
}

#[cfg(feature = "private-service")]
#[derive(Debug, Args)]
struct PrivateServeArgs {
    /// Explicitly allow the qualification-only, non-oblivious backend to listen.
    #[arg(long)]
    allow_qualification_backend: bool,

    /// Mainnet Zainod TOML config used to open the canonical indexed source.
    #[arg(long, value_name = "FILE")]
    config: PathBuf,

    /// Complete three-file capture directory bound to the sizing input.
    #[arg(long, value_name = "DIR")]
    capture_dir: PathBuf,

    /// Complete three-file sizing directory that fixes the projection shape.
    #[arg(long, value_name = "DIR")]
    sizing_dir: PathBuf,

    /// Directory holding this runtime's crash-durable replay journal.
    #[arg(long, value_name = "DIR")]
    replay_journal_dir: PathBuf,

    /// Address the private gRPC surface binds to.
    #[arg(long, value_name = "ADDR")]
    listen_address: SocketAddr,

    /// Emit projection-replay progress every this many public block heights.
    #[arg(long)]
    progress_interval: NonZeroU32,
}

#[cfg(feature = "typed-qualification")]
#[derive(Debug, Args)]
struct ReleaseCommand {
    #[command(subcommand)]
    command: ReleaseSubcommand,
}

#[cfg(feature = "typed-qualification")]
#[derive(Debug, Subcommand)]
enum ReleaseSubcommand {
    /// Record observed agreement between two fixed-procedure build artifacts.
    CreateReceipt(ReleaseCreateReceiptArgs),
    /// Check canonical receipt integrity and the running executable identity.
    VerifyReceipt(ReleaseVerifyReceiptArgs),
}

#[cfg(feature = "typed-qualification")]
#[derive(Debug, Args)]
struct ReleaseCreateReceiptArgs {
    /// Exact full source revision reported for both build procedures.
    #[arg(long)]
    source_revision: String,

    /// Git archive whose embedded commit and fixed inputs are checked locally.
    #[arg(long, value_name = "FILE")]
    source_archive: PathBuf,

    /// Cargo.lock reported as consumed by both build procedures.
    #[arg(long, value_name = "FILE")]
    cargo_lock: PathBuf,

    /// rust-toolchain.toml reported as consumed by both build procedures.
    #[arg(long, value_name = "FILE")]
    rust_toolchain: PathBuf,

    /// Dockerfile.deterministic reported as consumed by both build procedures.
    #[arg(long, value_name = "FILE")]
    dockerfile: PathBuf,

    /// Primary zainod-oram artifact, which must be this invoking executable.
    #[arg(long, value_name = "FILE")]
    binary: PathBuf,

    /// Second no-cache build artifact that must have the same bytes.
    #[arg(long, value_name = "FILE")]
    reproducible_binary: PathBuf,

    /// New path that will receive the canonical receipt JSON.
    #[arg(long, value_name = "FILE")]
    output: PathBuf,
}

#[cfg(feature = "typed-qualification")]
#[derive(Debug, Args)]
struct ReleaseVerifyReceiptArgs {
    /// Canonical receipt to check against the running /proc/self/exe inode.
    #[arg(long, value_name = "FILE")]
    receipt: PathBuf,
}

#[derive(Debug, Args)]
struct QualificationCommand {
    #[command(subcommand)]
    command: QualificationSubcommand,
}

#[derive(Debug, Subcommand)]
enum QualificationSubcommand {
    /// Run the fixed correctness scenario and publish aggregate evidence.
    #[cfg(feature = "typed-qualification")]
    Run(QualificationRunArgs),
    /// Run a fixed stress profile and publish aggregate evidence.
    #[cfg(feature = "typed-qualification")]
    Stress(QualificationStressArgs),
    /// Run a sizing-bound builder target-load profile and publish aggregate evidence.
    #[cfg(feature = "typed-qualification")]
    TargetLoad(QualificationTargetLoadArgs),
    /// Rebuild a typed worker from a fixed canonical source snapshot.
    #[cfg(feature = "typed-qualification")]
    ColdRebuild(QualificationColdRebuildArgs),
    /// Derive a pinned-Rostl retained-memory floor from an admitted hybrid bundle.
    #[cfg(feature = "typed-qualification")]
    FixedPageCapacity(QualificationFixedPageCapacityArgs),
    /// Create, inspect, and verify a Gate 2 timing matrix manifest.
    #[cfg(feature = "typed-qualification")]
    Timing(QualificationTimingCommand),
    /// Replay a fixed source snapshot and qualify insertion failure against a declared budget.
    InsertionBound(QualificationInsertionBoundArgs),
    /// Replay a checkpoint-preverified source and measure neutral hybrid-sizing evidence.
    HybridSizing(QualificationHybridSizingArgs),
}

#[cfg(feature = "typed-qualification")]
#[derive(Debug, Args)]
struct QualificationTimingCommand {
    #[command(subcommand)]
    command: QualificationTimingSubcommand,
}

#[cfg(feature = "typed-qualification")]
#[derive(Debug, Subcommand)]
enum QualificationTimingSubcommand {
    /// Create an immutable receipt- and host-bound timing manifest.
    #[command(name = "create-manifest")]
    Create(QualificationTimingCreateManifestArgs),
    /// Structurally verify retained bytes against an externally retained digest.
    #[command(name = "inspect-manifest")]
    Inspect(QualificationTimingInspectManifestArgs),
    /// Revalidate same-boot execution admission against this binary and host.
    #[command(name = "verify-manifest")]
    Verify(QualificationTimingVerifyManifestArgs),
    /// Run exactly the next unconsumed manifest cell with a durable start link.
    #[command(name = "run-cell")]
    RunCell(QualificationTimingRunCellArgs),
    /// Inspect the retained attempt chain, optionally against an external head.
    #[command(name = "inspect-ledger")]
    InspectLedger(QualificationTimingInspectLedgerArgs),
    /// Consume a crash-left started cell without rerunning its timing workload.
    #[command(name = "seal-dangling")]
    SealDangling(QualificationTimingSealDanglingArgs),
}

#[cfg(feature = "typed-qualification")]
#[derive(Debug, Args)]
struct QualificationTimingCreateManifestArgs {
    /// Strict manifest-request-v1 JSON containing every matrix axis and threshold.
    #[arg(long, value_name = "FILE")]
    request: PathBuf,

    /// Canonical release receipt for this invoking zainod-oram executable.
    #[arg(long, value_name = "FILE")]
    release_receipt: PathBuf,

    /// New directory that will receive manifest.json and the exact receipt bytes.
    #[arg(long, value_name = "DIR")]
    output_dir: PathBuf,
}

#[cfg(feature = "typed-qualification")]
#[derive(Debug, Args)]
struct QualificationTimingVerifyManifestArgs {
    /// Complete two-file timing-manifest artifact directory.
    #[arg(long, value_name = "DIR")]
    manifest_dir: PathBuf,

    /// Canonical release receipt for this invoking zainod-oram executable.
    #[arg(long, value_name = "FILE")]
    release_receipt: PathBuf,

    /// Externally retained BLAKE2s-256 digest of canonical manifest.json.
    #[arg(long, value_name = "HEX")]
    expected_manifest_blake2s256: String,
}

#[cfg(feature = "typed-qualification")]
#[derive(Debug, Args)]
struct QualificationTimingInspectManifestArgs {
    /// Complete two-file timing-manifest artifact directory.
    #[arg(long, value_name = "DIR")]
    manifest_dir: PathBuf,

    /// Externally retained BLAKE2s-256 digest of canonical manifest.json.
    #[arg(long, value_name = "HEX")]
    expected_manifest_blake2s256: String,
}

#[cfg(feature = "typed-qualification")]
#[derive(Debug, Args)]
struct QualificationTimingRunCellArgs {
    /// Complete two-file timing-manifest artifact directory.
    #[arg(long, value_name = "DIR")]
    manifest_dir: PathBuf,

    /// Canonical release receipt for this invoking zainod-oram executable.
    #[arg(long, value_name = "FILE")]
    release_receipt: PathBuf,

    /// Externally retained BLAKE2s-256 digest of canonical manifest.json.
    #[arg(long, value_name = "HEX")]
    expected_manifest_blake2s256: String,

    /// Existing real directory that holds immutable numeric attempt links.
    #[arg(long, value_name = "DIR")]
    ledger_dir: PathBuf,
}

#[cfg(feature = "typed-qualification")]
#[derive(Debug, Args)]
struct QualificationTimingInspectLedgerArgs {
    /// Complete two-file timing-manifest artifact directory.
    #[arg(long, value_name = "DIR")]
    manifest_dir: PathBuf,

    /// Externally retained BLAKE2s-256 digest of canonical manifest.json.
    #[arg(long, value_name = "HEX")]
    expected_manifest_blake2s256: String,

    /// Existing real directory that holds immutable numeric attempt links.
    #[arg(long, value_name = "DIR")]
    ledger_dir: PathBuf,

    /// Optional externally retained final link sequence.
    #[arg(long, requires = "expected_head_blake2s256")]
    expected_head_sequence: Option<u64>,

    /// Optional externally retained final record digest.
    #[arg(long, value_name = "HEX", requires = "expected_head_sequence")]
    expected_head_blake2s256: Option<String>,
}

#[cfg(feature = "typed-qualification")]
#[derive(Debug, Args)]
struct QualificationTimingSealDanglingArgs {
    /// Complete two-file timing-manifest artifact directory.
    #[arg(long, value_name = "DIR")]
    manifest_dir: PathBuf,

    /// Externally retained BLAKE2s-256 digest of canonical manifest.json.
    #[arg(long, value_name = "HEX")]
    expected_manifest_blake2s256: String,

    /// Existing real directory whose final link is a dangling started state.
    #[arg(long, value_name = "DIR")]
    ledger_dir: PathBuf,
}

#[cfg(feature = "typed-qualification")]
#[derive(Debug, Args)]
struct QualificationRunArgs {
    /// New directory that will receive the complete verified evidence artifact.
    #[arg(long, value_name = "DIR")]
    output_dir: PathBuf,
}

#[cfg(feature = "typed-qualification")]
#[derive(Debug, Args)]
struct QualificationStressArgs {
    /// Versioned fixed stress profile to execute.
    #[arg(long, value_enum)]
    profile: StressQualificationProfileArg,

    /// New directory that will receive the complete verified evidence artifact.
    #[arg(long, value_name = "DIR")]
    output_dir: PathBuf,
}

#[cfg(feature = "typed-qualification")]
#[derive(Debug, Args)]
struct QualificationTargetLoadArgs {
    /// Versioned fixed builder target-load profile to execute.
    #[arg(long, value_enum)]
    profile: TargetLoadProfileArg,

    /// Complete three-file capture directory used as the analytical source.
    #[arg(long, value_name = "DIR")]
    capture_dir: PathBuf,

    /// Validated context lineage; its model values do not affect this analysis.
    #[arg(long, value_name = "DIR")]
    sizing_dir: PathBuf,

    /// New directory that will receive the complete verified evidence artifact.
    #[arg(long, value_name = "DIR")]
    output_dir: PathBuf,
}

#[cfg(feature = "typed-qualification")]
#[derive(Debug, Args)]
struct QualificationColdRebuildArgs {
    /// Versioned source-bound cold-rebuild profile to execute.
    #[arg(long, value_enum)]
    profile: ColdRebuildProfileArg,

    /// Mainnet Zainod TOML config used to open the canonical indexed source.
    #[arg(long, value_name = "FILE")]
    config: PathBuf,

    /// Complete three-file capture directory bound to the sizing input.
    #[arg(long, value_name = "DIR")]
    capture_dir: PathBuf,

    /// Complete three-file sizing directory to validate and consume.
    #[arg(long, value_name = "DIR")]
    sizing_dir: PathBuf,

    /// Declared allocation-through-readiness rebuild budget in whole seconds.
    #[arg(long)]
    declared_rebuild_budget_seconds: NonZeroU64,

    /// New directory that will receive the complete verified evidence artifact.
    #[arg(long, value_name = "DIR")]
    output_dir: PathBuf,

    /// Emit aggregate progress every this many public block heights.
    #[arg(long)]
    progress_interval: NonZeroU32,
}

#[derive(Debug, Args)]
struct QualificationInsertionBoundArgs {
    /// Versioned source-bound insertion-analysis profile to execute.
    #[arg(long, value_enum)]
    profile: InsertionBoundProfileArg,

    /// Mainnet Zainod TOML config used to open the canonical indexed source.
    #[arg(long, value_name = "FILE")]
    config: PathBuf,

    /// Complete three-file capture directory bound to the sizing input.
    #[arg(long, value_name = "DIR")]
    capture_dir: PathBuf,

    /// Complete three-file sizing directory to validate and consume.
    #[arg(long, value_name = "DIR")]
    sizing_dir: PathBuf,

    /// Maximum sampled failed-seed rate accepted, in basis points.
    #[arg(
        long,
        value_parser = clap::value_parser!(u64).range(0..=10_000)
    )]
    failure_budget_bps: u64,

    /// New directory that will receive the complete verified evidence artifact.
    #[arg(long, value_name = "DIR")]
    output_dir: PathBuf,

    /// Emit aggregate progress every this many public block heights.
    #[arg(long)]
    progress_interval: NonZeroU32,
}

#[derive(Debug, Args)]
struct QualificationHybridSizingArgs {
    /// Versioned source-bound hybrid-sizing profile to execute.
    #[arg(long, value_enum)]
    profile: HybridSizingProfileArg,

    /// Mainnet Zainod TOML config used to open the canonical indexed source.
    #[arg(long, value_name = "FILE")]
    config: PathBuf,

    /// Complete three-file capture directory bound to the sizing input.
    #[arg(long, value_name = "DIR")]
    capture_dir: PathBuf,

    /// Complete three-file sizing directory to validate and consume.
    #[arg(long, value_name = "DIR")]
    sizing_dir: PathBuf,

    /// New directory that will receive the complete verified evidence artifact.
    #[arg(long, value_name = "DIR")]
    output_dir: PathBuf,

    /// Emit aggregate progress every this many public block heights.
    #[arg(long)]
    progress_interval: NonZeroU32,
}

#[cfg(feature = "typed-qualification")]
#[derive(Debug, Args)]
struct QualificationFixedPageCapacityArgs {
    /// Exact retained three-file hybrid-sizing directory to consume.
    #[arg(long, value_name = "DIR")]
    hybrid_sizing_dir: PathBuf,

    /// Externally retained canonical hybrid-sizing BLAKE2s-256 digest.
    #[arg(long)]
    expected_hybrid_sizing_blake2s256: String,
}

#[cfg(feature = "typed-qualification")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum StressQualificationProfileArg {
    /// Fixed smoke-level stress qualification profile.
    #[value(name = "smoke-v1")]
    SmokeV1,
    /// Fixed full admitted-map correctness-saturation profile.
    #[value(name = "full-map-saturation-v1")]
    FullMapSaturationV1,
}

#[cfg(feature = "typed-qualification")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum TargetLoadProfileArg {
    /// Fixed single-caller profile for the generic Linux x86_64 builder.
    #[value(name = "builder-foundation-v1")]
    BuilderFoundationV1,
}

#[cfg(feature = "typed-qualification")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ColdRebuildProfileArg {
    /// Fixed source-bound single-caller profile for the generic builder.
    #[value(name = "source-bound-builder-v1")]
    SourceBoundBuilderV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum InsertionBoundProfileArg {
    /// Exact source replay using eight fixed schedules for the current four-probe layout.
    #[value(name = "current-four-probe-v1")]
    CurrentFourProbeV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum HybridSizingProfileArg {
    /// Exact source replay measuring live-UTXO base and delta demand.
    #[value(name = "live-utxo-base-delta-v1")]
    LiveUtxoBaseDeltaV1,
    /// V1 replay plus the fixed source-bound growth profile.
    #[value(name = "live-utxo-base-delta-growth-v2")]
    LiveUtxoBaseDeltaGrowthV2,
}

#[derive(Debug, Args)]
struct CorpusCommand {
    #[command(subcommand)]
    command: CorpusSubcommand,
}

#[derive(Debug, Subcommand)]
enum CorpusSubcommand {
    /// Capture one fixed canonical mainnet snapshot into an atomic artifact directory.
    Capture(CorpusCaptureArgs),
    /// Apply explicit sizing assumptions to a validated capture without node access.
    Size(CorpusSizeArgs),
    /// Revalidate an existing sizing artifact against its source capture.
    ValidateSizing(CorpusValidateSizingArgs),
}

#[derive(Debug, Args)]
struct CorpusCaptureArgs {
    /// Zainod TOML config. The config and connected validator must be mainnet.
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// New directory that will receive the complete verified capture artifact.
    #[arg(long, value_name = "DIR")]
    output_dir: PathBuf,

    /// Emit aggregate progress every this many public block heights.
    #[arg(long, default_value = "10000")]
    progress_interval: NonZeroU32,

    /// Maximum indexed-block fetches in flight; results are always reduced by height.
    #[arg(
        long,
        default_value = "1",
        value_parser = parse_capture_fetch_concurrency
    )]
    fetch_concurrency: NonZeroUsize,

    /// Public height to capture instead of the snapshot's serviceable tip.
    #[arg(long, requires = "target_hash")]
    target_height: Option<u32>,

    /// RPC-order block hash paired with --target-height.
    #[arg(long, value_name = "HEX", requires = "target_height")]
    target_hash: Option<String>,
}

#[derive(Debug, Args)]
struct CorpusSizeArgs {
    /// Complete three-file corpus capture directory to validate and consume.
    #[arg(long, value_name = "DIR")]
    input_dir: PathBuf,

    /// New directory that will receive the complete verified sizing artifact.
    #[arg(long, value_name = "DIR")]
    output_dir: PathBuf,

    /// Number of annual proportional-growth steps to model.
    #[arg(long)]
    growth_horizon_years: u16,

    /// Annual proportional address-count growth in basis points.
    #[arg(long)]
    annual_growth_bps: u64,

    /// Allocated directory-table slots; must be a supported power of two.
    #[arg(long)]
    directory_capacity: u64,

    /// Maximum admitted directory records, strictly below capacity.
    #[arg(long)]
    directory_admission_limit: u64,

    /// Allocated event-table slots; must be a supported power of two.
    #[arg(long)]
    event_capacity: u64,

    /// Maximum admitted event records, strictly below capacity.
    #[arg(long)]
    event_admission_limit: u64,

    /// Maximum admitted event history for any one standard address.
    #[arg(long)]
    max_events_per_address: u64,

    /// Modeled bytes for each complete position-map domain entry.
    #[arg(long)]
    position_map_entry_bytes: u64,

    /// Operator-supplied backend memory expansion in basis points; at least 10000.
    #[arg(long)]
    backend_expansion_bps: u64,

    /// Operator-supplied TDX memory envelope in bytes; not a measured value.
    #[arg(long)]
    tdx_memory_bytes: u64,

    /// Reserved memory headroom in basis points; must be below 10000.
    #[arg(long)]
    required_headroom_bps: u64,
}

#[derive(Debug, Args)]
struct CorpusValidateSizingArgs {
    /// Complete three-file corpus capture directory to validate and consume.
    #[arg(long, value_name = "DIR")]
    capture_dir: PathBuf,

    /// Complete three-file sizing directory to revalidate against the capture.
    #[arg(long, value_name = "DIR")]
    sizing_dir: PathBuf,
}

impl CorpusSizeArgs {
    fn model(&self) -> Result<MainnetSizingModel, zaino_oram::MainnetCorpusError> {
        MainnetSizingModel::new(
            self.growth_horizon_years,
            self.annual_growth_bps,
            self.directory_capacity,
            self.directory_admission_limit,
            self.event_capacity,
            self.event_admission_limit,
            self.max_events_per_address,
            self.position_map_entry_bytes,
            self.backend_expansion_bps,
            self.tdx_memory_bytes,
            self.required_headroom_bps,
        )
    }
}

fn main() -> ExitCode {
    match run_from_cli(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ORAM research runner failed: {error}");
            ExitCode::FAILURE
        }
    }
}

enum RunnerDispatch {
    #[cfg(feature = "typed-qualification")]
    TimingCell(QualificationTimingRunCellArgs),
    Async(Cli),
}

fn classify_runner_dispatch(cli: Cli) -> RunnerDispatch {
    match cli.command {
        #[cfg(feature = "typed-qualification")]
        Command::Qualification(QualificationCommand {
            command:
                QualificationSubcommand::Timing(QualificationTimingCommand {
                    command: QualificationTimingSubcommand::RunCell(args),
                }),
        }) => RunnerDispatch::TimingCell(args),
        command => RunnerDispatch::Async(Cli { command }),
    }
}

fn run_from_cli(cli: Cli) -> RunnerResult<()> {
    match classify_runner_dispatch(cli) {
        #[cfg(feature = "typed-qualification")]
        RunnerDispatch::TimingCell(args) => run_timing_cell(args),
        RunnerDispatch::Async(cli) => {
            zaino_common::logging::init();
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(run(cli))
        }
    }
}

async fn run(cli: Cli) -> RunnerResult<()> {
    match cli.command {
        Command::Corpus(command) => match command.command {
            CorpusSubcommand::Capture(args) => run_corpus_capture(args).await,
            CorpusSubcommand::Size(args) => run_corpus_size(args),
            CorpusSubcommand::ValidateSizing(args) => run_corpus_validate_sizing(args),
        },
        #[cfg(feature = "typed-qualification")]
        Command::Release(command) => match command.command {
            ReleaseSubcommand::CreateReceipt(args) => run_release_create_receipt(args),
            ReleaseSubcommand::VerifyReceipt(args) => run_release_verify_receipt(args),
        },
        Command::Qualification(command) => match command.command {
            #[cfg(feature = "typed-qualification")]
            QualificationSubcommand::Run(args) => run_qualification(args),
            #[cfg(feature = "typed-qualification")]
            QualificationSubcommand::Stress(args) => run_stress_qualification(args),
            #[cfg(feature = "typed-qualification")]
            QualificationSubcommand::TargetLoad(args) => run_target_load(args),
            #[cfg(feature = "typed-qualification")]
            QualificationSubcommand::ColdRebuild(args) => run_cold_rebuild(args).await,
            #[cfg(feature = "typed-qualification")]
            QualificationSubcommand::FixedPageCapacity(args) => run_fixed_page_capacity(args),
            #[cfg(feature = "typed-qualification")]
            QualificationSubcommand::Timing(command) => match command.command {
                QualificationTimingSubcommand::Create(args) => run_timing_create_manifest(args),
                QualificationTimingSubcommand::Inspect(args) => run_timing_inspect_manifest(args),
                QualificationTimingSubcommand::Verify(args) => run_timing_verify_manifest(args),
                QualificationTimingSubcommand::RunCell(_) => {
                    Err(RunnerError::TimingAttemptRequiresSynchronousDispatch.into())
                }
                QualificationTimingSubcommand::InspectLedger(args) => {
                    run_timing_inspect_ledger(args)
                }
                QualificationTimingSubcommand::SealDangling(args) => run_timing_seal_dangling(args),
            },
            QualificationSubcommand::InsertionBound(args) => run_insertion_bound(args).await,
            QualificationSubcommand::HybridSizing(args) => run_hybrid_sizing(args).await,
        },
        #[cfg(feature = "private-service")]
        Command::Private(command) => match command.command {
            PrivateSubcommand::Serve(args) => run_private_serve(args).await,
        },
    }
}

#[cfg(feature = "typed-qualification")]
fn run_fixed_page_capacity(args: QualificationFixedPageCapacityArgs) -> RunnerResult<()> {
    let hybrid = load_hybrid_sizing(
        &args.hybrid_sizing_dir,
        &args.expected_hybrid_sizing_blake2s256,
    )?;
    let lower_bound = derive_fixed_page_capacity_lower_bound(hybrid.report())?;
    println!(
        "hybrid_sizing_blake2s256={}\n{}",
        hybrid.hybrid_sizing_blake2s256(),
        lower_bound
    );
    Ok(())
}

#[cfg(feature = "typed-qualification")]
fn run_timing_create_manifest(args: QualificationTimingCreateManifestArgs) -> RunnerResult<()> {
    let output_dir = args.output_dir.clone();
    let summary = create_timing_manifest(
        TimingManifestCreateInputs {
            request: args.request,
            release_receipt: args.release_receipt,
            output_dir: args.output_dir,
        },
        env!("CARGO_PKG_VERSION"),
    )?;
    println!(
        "timing_manifest={},manifest_blake2s256:{},cells:{}",
        output_dir.display(),
        summary.manifest_blake2s256(),
        summary.cell_count()
    );
    Ok(())
}

#[cfg(feature = "typed-qualification")]
fn run_timing_verify_manifest(args: QualificationTimingVerifyManifestArgs) -> RunnerResult<()> {
    let manifest_dir = args.manifest_dir.clone();
    let summary = verify_timing_manifest(
        TimingManifestVerifyInputs {
            manifest_dir: args.manifest_dir,
            release_receipt: args.release_receipt,
            expected_manifest_blake2s256: args.expected_manifest_blake2s256,
        },
        env!("CARGO_PKG_VERSION"),
    )?;
    println!(
        "timing_manifest_verified={},manifest_blake2s256:{},cells:{}",
        manifest_dir.display(),
        summary.manifest_blake2s256(),
        summary.cell_count()
    );
    Ok(())
}

#[cfg(feature = "typed-qualification")]
fn run_timing_inspect_manifest(args: QualificationTimingInspectManifestArgs) -> RunnerResult<()> {
    let manifest_dir = args.manifest_dir.clone();
    let summary = inspect_timing_manifest(TimingManifestInspectInputs {
        manifest_dir: args.manifest_dir,
        expected_manifest_blake2s256: args.expected_manifest_blake2s256,
    })?;
    println!(
        "timing_manifest_inspected={},manifest_blake2s256:{},cells:{}",
        manifest_dir.display(),
        summary.manifest_blake2s256(),
        summary.cell_count()
    );
    Ok(())
}

#[cfg(feature = "typed-qualification")]
fn run_timing_cell(args: QualificationTimingRunCellArgs) -> RunnerResult<()> {
    let outcome = run_timing_attempt(
        TimingAttemptRunInputs {
            manifest_dir: args.manifest_dir,
            release_receipt: args.release_receipt,
            expected_manifest_blake2s256: args.expected_manifest_blake2s256,
            ledger_dir: args.ledger_dir,
        },
        env!("CARGO_PKG_VERSION"),
    )?;
    match outcome {
        TimingAttemptOutcome::Completed(summary) => {
            print_timing_attempt_summary(&summary);
            match summary.terminal_state() {
                TimingAttemptTerminalState::CompletedPositive => Ok(()),
                TimingAttemptTerminalState::CompletedNegative => {
                    Err(RunnerError::TimingAttemptNegative {
                        cell_id: summary.cell_id().to_owned(),
                    }
                    .into())
                }
                TimingAttemptTerminalState::StartedError => {
                    Err(RunnerError::TimingAttemptUnexpectedTerminal.into())
                }
            }
        }
        TimingAttemptOutcome::ExecutionError { summary, source } => {
            print_timing_attempt_summary(&summary);
            Err(source)
        }
    }
}

#[cfg(feature = "typed-qualification")]
fn run_timing_inspect_ledger(args: QualificationTimingInspectLedgerArgs) -> RunnerResult<()> {
    let summary = inspect_timing_attempt_ledger(TimingAttemptInspectInputs {
        manifest_dir: args.manifest_dir,
        expected_manifest_blake2s256: args.expected_manifest_blake2s256,
        ledger_dir: args.ledger_dir,
        expected_head_sequence: args.expected_head_sequence,
        expected_head_blake2s256: args.expected_head_blake2s256,
    })?;
    let head = summary.head().map_or_else(
        || "none".to_owned(),
        |(sequence, digest)| format!("{sequence}:{digest}"),
    );
    println!(
        "timing_ledger=valid,manifest_blake2s256:{},cells:{},started:{},terminal:{},positive:{},negative:{},started_error:{},dangling:{},head:{},externally_witnessed:{},all_cells_terminal:{},wall_clock_matrix_recomputed_positive:{},can_clear_gate2:false",
        summary.manifest_blake2s256(),
        summary.cell_count(),
        summary.started_cells(),
        summary.terminal_cells(),
        summary.positive_cells(),
        summary.negative_cells(),
        summary.started_error_cells(),
        summary.dangling_cell_id().unwrap_or("none"),
        head,
        summary.externally_witnessed(),
        summary.all_cells_terminal(),
        summary.wall_clock_matrix_recomputed_positive(),
    );
    Ok(())
}

#[cfg(feature = "typed-qualification")]
fn run_timing_seal_dangling(args: QualificationTimingSealDanglingArgs) -> RunnerResult<()> {
    let summary = seal_dangling_timing_attempt(
        TimingAttemptSealInputs {
            manifest_dir: args.manifest_dir,
            expected_manifest_blake2s256: args.expected_manifest_blake2s256,
            ledger_dir: args.ledger_dir,
        },
        env!("CARGO_PKG_VERSION"),
    )?;
    print_timing_attempt_summary(&summary);
    Ok(())
}

#[cfg(feature = "typed-qualification")]
fn print_timing_attempt_summary(summary: &TimingAttemptSummary) {
    println!(
        "timing_attempt=retained,cell:{},state:{},head_sequence:{},head_blake2s256:{}",
        summary.cell_id(),
        timing_attempt_terminal_state_name(summary.terminal_state()),
        summary.head_sequence(),
        summary.head_blake2s256(),
    );
}

#[cfg(feature = "typed-qualification")]
const fn timing_attempt_terminal_state_name(state: TimingAttemptTerminalState) -> &'static str {
    match state {
        TimingAttemptTerminalState::CompletedPositive => "completed_positive",
        TimingAttemptTerminalState::CompletedNegative => "completed_negative",
        TimingAttemptTerminalState::StartedError => "started_error",
    }
}

#[cfg(feature = "typed-qualification")]
fn run_release_create_receipt(args: ReleaseCreateReceiptArgs) -> RunnerResult<()> {
    let output = args.output.clone();
    create_release_receipt(ReleaseReceiptInputs {
        source_revision: args.source_revision,
        source_archive: args.source_archive,
        cargo_lock: args.cargo_lock,
        rust_toolchain: args.rust_toolchain,
        dockerfile: args.dockerfile,
        binary: args.binary,
        reproducible_binary: args.reproducible_binary,
        output: args.output,
    })?;
    println!("release_receipt={}", output.display());
    Ok(())
}

#[cfg(feature = "typed-qualification")]
fn run_release_verify_receipt(args: ReleaseVerifyReceiptArgs) -> RunnerResult<()> {
    verify_release_receipt(&args.receipt)?;
    println!("release_receipt_verified={}", args.receipt.display());
    Ok(())
}

#[cfg(feature = "typed-qualification")]
fn run_qualification(args: QualificationRunArgs) -> RunnerResult<()> {
    let qualification = run_typed_worker_qualification()?;
    publish_qualification(&args.output_dir, &qualification, env!("CARGO_PKG_VERSION"))?;
    println!("qualification_artifact={}", args.output_dir.display());
    Ok(())
}

#[cfg(feature = "typed-qualification")]
fn run_stress_qualification(args: QualificationStressArgs) -> RunnerResult<()> {
    match args.profile {
        StressQualificationProfileArg::SmokeV1 => {
            let qualification =
                run_typed_worker_stress_qualification(TypedWorkerStressProfile::SmokeV1)?;
            publish_stress_qualification(
                &args.output_dir,
                &qualification,
                env!("CARGO_PKG_VERSION"),
            )?;
            println!(
                "stress_qualification_artifact={}",
                args.output_dir.display()
            );
        }
        StressQualificationProfileArg::FullMapSaturationV1 => {
            let full_map_saturation = run_typed_worker_full_map_saturation(
                TypedWorkerFullMapSaturationProfile::FullMapSaturationV1,
            )?;
            publish_full_map_saturation(
                &args.output_dir,
                &full_map_saturation,
                env!("CARGO_PKG_VERSION"),
            )?;
            println!("full_map_saturation_artifact={}", args.output_dir.display());
        }
    }
    Ok(())
}

#[cfg(feature = "typed-qualification")]
fn run_target_load(args: QualificationTargetLoadArgs) -> RunnerResult<()> {
    let capture = load_capture(&args.capture_dir)?;
    let sizing = load_sizing(&args.sizing_dir, &capture)?;
    let profile = match args.profile {
        TargetLoadProfileArg::BuilderFoundationV1 => {
            TypedWorkerTargetLoadProfile::BuilderFoundationV1
        }
    };
    let target_load = run_typed_worker_target_load(
        profile,
        sizing.qualification(),
        sizing.measurement_blake2s256(),
        sizing.qualification_blake2s256(),
    )?;
    publish_target_load(
        &args.output_dir,
        &capture,
        &sizing,
        &target_load,
        env!("CARGO_PKG_VERSION"),
    )?;
    println!("target_load_artifact={}", args.output_dir.display());
    Ok(())
}

async fn run_insertion_bound(args: QualificationInsertionBoundArgs) -> RunnerResult<()> {
    let capture = load_capture(&args.capture_dir)?;
    let sizing = load_sizing(&args.sizing_dir, &capture)?;
    let config = load_config(&args.config)?;
    if config.network != Network::Mainnet {
        return Err(RunnerError::MainnetRequired {
            configured: config.network,
        }
        .into());
    }

    let profile = match args.profile {
        InsertionBoundProfileArg::CurrentFourProbeV1 => {
            SourceBoundInsertionBudgetProfile::CurrentFourProbeV1
        }
    };
    let source_backend = backend_kind(config.backend);
    let service_config = NodeBackedIndexerServiceConfig::try_from(config)?;
    let mut service = NodeBackedIndexerService::spawn(service_config).await?;
    let analysis_result = analyze_insertion_bound_fixed_snapshot(
        &service,
        profile,
        &capture,
        &sizing,
        args.failure_budget_bps,
        source_backend,
        args.progress_interval,
    )
    .await;
    service.close();
    let (report, source_snapshot) = analysis_result?;

    publish_insertion_bound(
        &args.output_dir,
        &capture,
        &sizing,
        &report,
        args.failure_budget_bps,
        &source_snapshot,
        env!("CARGO_PKG_VERSION"),
    )?;
    println!("insertion_bound_artifact={}", args.output_dir.display());
    if report.is_go() {
        Ok(())
    } else {
        Err(RunnerError::InsertionFailureBudgetMiss {
            failure_budget_bps: args.failure_budget_bps,
        }
        .into())
    }
}

async fn run_hybrid_sizing(args: QualificationHybridSizingArgs) -> RunnerResult<()> {
    let capture = load_capture(&args.capture_dir)?;
    let sizing = load_sizing(&args.sizing_dir, &capture)?;
    let config = load_config(&args.config)?;
    if config.network != Network::Mainnet {
        return Err(RunnerError::MainnetRequired {
            configured: config.network,
        }
        .into());
    }

    let profile = match args.profile {
        HybridSizingProfileArg::LiveUtxoBaseDeltaV1 => {
            SourceBoundHybridSizingProfile::LiveUtxoBaseDeltaV1
        }
        HybridSizingProfileArg::LiveUtxoBaseDeltaGrowthV2 => {
            SourceBoundHybridSizingProfile::LiveUtxoBaseDeltaGrowthV2
        }
    };
    let source_backend = backend_kind(config.backend);
    let service_config = NodeBackedIndexerServiceConfig::try_from(config)?;
    let mut service = NodeBackedIndexerService::spawn(service_config).await?;
    let analysis_result = analyze_hybrid_sizing_fixed_snapshot(
        &service,
        profile,
        &capture,
        source_backend,
        args.progress_interval,
    )
    .await;
    service.close();
    let (report, source_snapshot) = analysis_result?;

    publish_hybrid_sizing(
        &args.output_dir,
        &capture,
        &sizing,
        &report,
        &source_snapshot,
        env!("CARGO_PKG_VERSION"),
    )?;
    println!(
        "hybrid_sizing_evidence_artifact={}",
        args.output_dir.display()
    );
    println!("hybrid_sizing_verdict=not-assessed");
    Ok(())
}

#[cfg(feature = "typed-qualification")]
async fn run_cold_rebuild(args: QualificationColdRebuildArgs) -> RunnerResult<()> {
    let capture = load_capture(&args.capture_dir)?;
    let sizing = load_sizing(&args.sizing_dir, &capture)?;
    let config = load_config(&args.config)?;
    if config.network != Network::Mainnet {
        return Err(RunnerError::MainnetRequired {
            configured: config.network,
        }
        .into());
    }

    let profile = match args.profile {
        ColdRebuildProfileArg::SourceBoundBuilderV1 => {
            TypedWorkerColdRebuildProfile::SourceBoundBuilderV1
        }
    };
    let declared_rebuild_budget = Duration::from_secs(args.declared_rebuild_budget_seconds.get());
    let source_backend = backend_kind(config.backend);
    let service_config = NodeBackedIndexerServiceConfig::try_from(config)?;
    let mut service = NodeBackedIndexerService::spawn(service_config).await?;
    let rebuild_result = rebuild_fixed_snapshot(
        &service,
        profile,
        &capture,
        &sizing,
        declared_rebuild_budget,
        source_backend,
        args.progress_interval,
    )
    .await;
    service.close();
    let (report, source_snapshot) = rebuild_result?;

    publish_cold_rebuild(
        &args.output_dir,
        &capture,
        &sizing,
        &report,
        declared_rebuild_budget,
        &source_snapshot,
        env!("CARGO_PKG_VERSION"),
    )?;
    println!("cold_rebuild_artifact={}", args.output_dir.display());
    if report.declared_rebuild_budget_passed() {
        Ok(())
    } else {
        Err(RunnerError::DeclaredRebuildBudgetMiss {
            declared_seconds: args.declared_rebuild_budget_seconds.get(),
        }
        .into())
    }
}

#[cfg(feature = "typed-qualification")]
async fn rebuild_fixed_snapshot(
    service: &NodeBackedIndexerService,
    profile: TypedWorkerColdRebuildProfile,
    capture: &ValidatedCapture,
    sizing: &ValidatedSizing,
    declared_rebuild_budget: Duration,
    source_backend: BackendKind,
    progress_interval: NonZeroU32,
) -> RunnerResult<(TypedWorkerColdRebuildReport, PreverifiedSourceSnapshotV1)> {
    replay_preverified_snapshot(
        service,
        capture,
        source_backend,
        progress_interval,
        "cold_rebuild",
        || {
            Ok(TypedWorkerColdRebuildSession::start(
                profile,
                capture.measurement(),
                sizing.qualification(),
                capture.measurement_blake2s256(),
                sizing.qualification_blake2s256(),
                declared_rebuild_budget,
            )?)
        },
        |session, block| {
            session.push(block)?;
            Ok(())
        },
        |session| {
            let report = session.finish()?;
            report.validate_against(
                capture.measurement(),
                sizing.qualification(),
                capture.measurement_blake2s256(),
                sizing.qualification_blake2s256(),
                declared_rebuild_budget,
            )?;
            Ok(report)
        },
    )
    .await
}

async fn analyze_insertion_bound_fixed_snapshot(
    service: &NodeBackedIndexerService,
    profile: SourceBoundInsertionBudgetProfile,
    capture: &ValidatedCapture,
    sizing: &ValidatedSizing,
    failure_budget_bps: u64,
    source_backend: BackendKind,
    progress_interval: NonZeroU32,
) -> RunnerResult<(
    SourceBoundInsertionBudgetReport,
    PreverifiedSourceSnapshotV1,
)> {
    replay_preverified_snapshot(
        service,
        capture,
        source_backend,
        progress_interval,
        "insertion_bound",
        || {
            Ok(SourceBoundInsertionBudgetSession::start(
                profile,
                capture.measurement(),
                sizing.qualification(),
                capture.measurement_blake2s256(),
                sizing.qualification_blake2s256(),
                failure_budget_bps,
            )?)
        },
        |session, block| {
            session.push(block)?;
            Ok(())
        },
        |session| {
            let report = session.finish()?;
            report.validate_against(
                capture.measurement(),
                sizing.qualification(),
                capture.measurement_blake2s256(),
                sizing.qualification_blake2s256(),
                failure_budget_bps,
            )?;
            Ok(report)
        },
    )
    .await
}

async fn analyze_hybrid_sizing_fixed_snapshot(
    service: &NodeBackedIndexerService,
    profile: SourceBoundHybridSizingProfile,
    capture: &ValidatedCapture,
    source_backend: BackendKind,
    progress_interval: NonZeroU32,
) -> RunnerResult<(SourceBoundHybridSizingReport, PreverifiedSourceSnapshotV1)> {
    replay_preverified_snapshot(
        service,
        capture,
        source_backend,
        progress_interval,
        "hybrid_sizing",
        || {
            Ok(SourceBoundHybridSizingSession::start(
                profile,
                capture.measurement(),
                capture.measurement_blake2s256(),
            )?)
        },
        |session, block| {
            session.push(block)?;
            Ok(())
        },
        |session| {
            let report = session.finish()?;
            report.validate_against(capture.measurement(), capture.measurement_blake2s256())?;
            Ok(report)
        },
    )
    .await
}

/// Record-schema and key-epoch version this runner composes runtimes at.
///
/// Fixed rather than configurable: both are bound into the serving identity a
/// refresh pins, so a runner that let them drift would produce projections no
/// runtime could recognise.
#[cfg(feature = "private-service")]
const PRIVATE_SCHEMA_VERSION: u32 = 1;
#[cfg(feature = "private-service")]
const PRIVATE_KEY_EPOCH: u64 = 1;

/// Rebuilds the projection this process will serve, then serves it.
///
/// Binding happens before the indexer is spawned so a port collision is
/// reported as such rather than after a full chain replay has been paid for.
#[cfg(feature = "private-service")]
async fn run_private_serve(args: PrivateServeArgs) -> RunnerResult<()> {
    require_private_listener_opt_in(args.allow_qualification_backend)?;
    eprintln!(
        "WARNING: private-query listener uses a qualification-only backend; it provides no physical obliviousness"
    );
    let capture = load_capture(&args.capture_dir)?;
    let sizing = load_sizing(&args.sizing_dir, &capture)?;
    let config = load_config(&args.config)?;
    if config.network != Network::Mainnet {
        return Err(RunnerError::MainnetRequired {
            configured: config.network,
        }
        .into());
    }
    let source_backend = backend_kind(config.backend);
    let shape = private_projection_shape(&capture, &sizing)?;

    let listener = PrivateQueryListener::bind(args.listen_address).await?;
    let listening_on = listener.local_addr();

    let service_config = NodeBackedIndexerServiceConfig::try_from(config)?;
    let mut service = NodeBackedIndexerService::spawn(service_config).await?;
    let served = serve_private_surface(
        &service,
        listener,
        listening_on,
        &capture,
        source_backend,
        args.progress_interval,
        shape,
        &args.replay_journal_dir,
    )
    .await;
    service.close();
    served
}

#[cfg(feature = "private-service")]
fn require_private_listener_opt_in(enabled: bool) -> RunnerResult<()> {
    if enabled {
        Ok(())
    } else {
        Err(RunnerError::PrivateListenerOptInRequired.into())
    }
}

/// Derives the projection dimensions from the validated sizing artifact.
///
/// Nothing here is a knob: the sizing artifact is the measured answer to how
/// wide the tables must be, and the seen/live output bounds come from the
/// capture the sizing was validated against.
#[cfg(feature = "private-service")]
fn private_projection_shape(
    capture: &ValidatedCapture,
    sizing: &ValidatedSizing,
) -> RunnerResult<PrivateProjectionShape> {
    let model = sizing.qualification().model();
    let outputs = usize::try_from(capture.measurement().output_count())
        .map_err(|_| RunnerError::PrivateProjectionUnavailable)?
        .max(1);
    let width = |value: u64| -> RunnerResult<usize> {
        usize::try_from(value).map_err(|_| RunnerError::PrivateProjectionUnavailable.into())
    };
    Ok(PrivateProjectionShape {
        network: PrivateNetwork::Mainnet,
        schema_version: PRIVATE_SCHEMA_VERSION,
        key_epoch: PRIVATE_KEY_EPOCH,
        projection_epoch: fresh_private_epoch()?,
        max_seen_outputs: outputs,
        max_live_outputs: outputs,
        directory_admission: width(model.directory_admission_limit())?,
        event_admission: width(model.event_admission_limit())?,
        max_events_per_address: width(model.max_events_per_address())?,
        directory_capacity: model.directory_capacity(),
        event_capacity: model.event_capacity(),
    })
}

/// A nonzero epoch no earlier run of this binary can collide with.
///
/// Wall-clock nanoseconds with the low bit forced: the epoch only has to
/// separate this process's durable state from a predecessor's, and a clock
/// that went backwards would produce a stale-looking epoch the journal's own
/// identity checks reject rather than a silently reused one.
#[cfg(feature = "private-service")]
fn fresh_private_epoch() -> RunnerResult<u64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RunnerError::PrivateProjectionUnavailable)?;
    Ok(u64::try_from(now.as_nanos() % u128::from(u64::MAX))
        .map_err(|_| RunnerError::PrivateProjectionUnavailable)?
        | 1)
}

/// Replays the finalized chain into a projection, pins it, and serves.
#[cfg(feature = "private-service")]
#[expect(
    clippy::too_many_arguments,
    reason = "every input is a distinct deployment decision; grouping them into \
              a struct used at exactly one call site would hide that"
)]
async fn serve_private_surface(
    service: &NodeBackedIndexerService,
    listener: PrivateQueryListener,
    listening_on: SocketAddr,
    capture: &ValidatedCapture,
    source_backend: BackendKind,
    progress_interval: NonZeroU32,
    shape: PrivateProjectionShape,
    replay_journal_dir: &Path,
) -> RunnerResult<()> {
    let (projection, _source_snapshot) = replay_preverified_snapshot(
        service,
        capture,
        source_backend,
        progress_interval,
        "private_projection",
        || {
            FinalizedProjectionBuilder::start(&shape)
                .map_err(|_| RunnerError::PrivateProjectionUnavailable.into())
        },
        |builder, block| {
            builder
                .push(block)
                .map_err(|_| RunnerError::PrivateProjectionUnavailable.into())
        },
        |builder| {
            builder
                .finish()
                .map_err(|_| RunnerError::PrivateProjectionUnavailable.into())
        },
    )
    .await?;
    let committed_height = projection.committed_height();

    let deployment = PrivateRuntimeDeployment {
        // The capture digest is already this deployment's public identity;
        // deriving the namespace from it keeps one more operator-supplied
        // identifier out of the surface.
        service_namespace_id: private_service_namespace_id(capture),
        owner_generation: fresh_private_epoch()?,
        replay_journal_root: replay_journal_dir.to_path_buf(),
        projection: shape,
    };
    let mut runtime = mainnet_private_query_runtime::<ValidatorConnector>(
        &deployment,
        PrivateRuntimeKeys::ephemeral().map_err(|_| RunnerError::PrivateRuntimeUnavailable)?,
    )
    .map_err(|_| RunnerError::PrivateRuntimeUnavailable)?;

    let subscriber = service.get_subscriber().inner();
    runtime
        .refresh(&subscriber.indexer, projection)
        .await
        .map_err(|_| RunnerError::PrivateRuntimeUnavailable)?;

    println!(
        "private_surface_listening={listening_on},committed_height:{committed_height},envelope_bytes:{PRIVATE_MAINNET_ENVELOPE_BYTES}"
    );
    listener
        .serve::<_, PRIVATE_MAINNET_ENVELOPE_BYTES>(runtime, async {
            // A failed signal registration must stop the server rather than
            // leave it serving with no way to be asked to stop.
            if let Err(error) = tokio::signal::ctrl_c().await {
                eprintln!("private_surface_shutdown=signal_unavailable,error:{error}");
            }
        })
        .await?;
    Ok(())
}

/// Binds the replay journal's namespace to the capture this service serves.
#[cfg(feature = "private-service")]
fn private_service_namespace_id(capture: &ValidatedCapture) -> [u8; 16] {
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, b"zainod-oram/private-service-namespace/v1\0");
    Digest::update(&mut hasher, capture.measurement_blake2s256().as_bytes());
    let digest = Digest::finalize(hasher);
    let mut namespace = [0; 16];
    namespace.copy_from_slice(&digest[..16]);
    namespace
}

#[expect(
    clippy::too_many_arguments,
    reason = "the helper keeps source preverification and ordered replay identical across consumers"
)]
async fn replay_preverified_snapshot<Session, Report>(
    service: &NodeBackedIndexerService,
    capture: &ValidatedCapture,
    source_backend: BackendKind,
    progress_interval: NonZeroU32,
    progress_label: &str,
    start: impl FnOnce() -> RunnerResult<Session>,
    mut push: impl FnMut(&mut Session, &IndexedBlock) -> RunnerResult<()>,
    finish: impl FnOnce(Session) -> RunnerResult<Report>,
) -> RunnerResult<(Report, PreverifiedSourceSnapshotV1)> {
    let subscriber = service.get_subscriber().inner();
    let snapshot = subscriber.indexer.snapshot_nonfinalized_state().await?;
    classify_snapshot(&snapshot)?;

    let checkpoint = capture.measurement().checkpoint();
    let checkpoint_height = checkpoint.height();
    let serviceable_height = u32::from(*snapshot.max_serviceable_height());
    if checkpoint_height > serviceable_height {
        return Err(RunnerError::CaptureCheckpointAboveServiceable {
            checkpoint: checkpoint_height,
            serviceable: serviceable_height,
        }
        .into());
    }
    let typed_checkpoint_height =
        Height::try_from(checkpoint_height).map_err(|_| RunnerError::HeightOutOfRange {
            height: checkpoint_height,
        })?;
    let actual_checkpoint_hash = subscriber
        .indexer
        .get_block_hash(&snapshot, typed_checkpoint_height)
        .await?
        .ok_or(RunnerError::MissingCanonicalBlock {
            height: checkpoint_height,
        })?;
    if !actual_checkpoint_hash
        .to_rpc_hex()
        .eq_ignore_ascii_case(checkpoint.hash())
    {
        return Err(RunnerError::CaptureCheckpointHashMismatch {
            height: checkpoint_height,
        }
        .into());
    }
    let source_snapshot = PreverifiedSourceSnapshotV1::new_verified(
        source_backend,
        serviceable_height,
        capture.measurement(),
    )?;

    // Consumer allocation begins only after the source snapshot has proven the
    // exact public capture checkpoint above.
    let mut session = start()?;
    eprintln!(
        "{progress_label}_start=mainnet,target_height:{checkpoint_height},serviceable_height:{serviceable_height}"
    );
    for raw_height in 0..=checkpoint_height {
        let height = Height::try_from(raw_height)
            .map_err(|_| RunnerError::HeightOutOfRange { height: raw_height })?;
        let block = subscriber
            .indexer
            .get_indexed_block_by_height(&snapshot, &height)
            .await?
            .ok_or(RunnerError::MissingCanonicalBlock { height: raw_height })?;
        push(&mut session, &block)?;
        if raw_height % progress_interval.get() == 0 || raw_height == checkpoint_height {
            eprintln!(
                "{progress_label}_progress=mainnet,current_height:{raw_height},target_height:{checkpoint_height}"
            );
        }
    }
    let report = finish(session)?;
    Ok((report, source_snapshot))
}

fn run_corpus_size(args: CorpusSizeArgs) -> RunnerResult<()> {
    let capture = load_capture(&args.input_dir)?;
    let model = args.model()?;
    let qualification = capture.measurement().apply_model(&model)?;
    publish_sizing(
        &args.output_dir,
        &capture,
        &qualification,
        env!("CARGO_PKG_VERSION"),
    )?;
    println!("sizing_artifact={}", args.output_dir.display());
    Ok(())
}

fn run_corpus_validate_sizing(args: CorpusValidateSizingArgs) -> RunnerResult<()> {
    let capture = load_capture(&args.capture_dir)?;
    let sizing = load_sizing(&args.sizing_dir, &capture)?;
    println!("{}", format_validated_sizing_summary(&sizing));
    Ok(())
}

fn format_validated_sizing_summary(sizing: &ValidatedSizing) -> String {
    let model = sizing.qualification().model();
    format!(
        "sizing_input=valid,measurement_blake2s256:{},qualification_blake2s256:{},directory_capacity:{},directory_admission_limit:{},event_capacity:{},event_admission_limit:{},max_events_per_address:{}",
        sizing.measurement_blake2s256(),
        sizing.qualification_blake2s256(),
        model.directory_capacity(),
        model.directory_admission_limit(),
        model.event_capacity(),
        model.event_admission_limit(),
        model.max_events_per_address(),
    )
}

async fn run_corpus_capture(args: CorpusCaptureArgs) -> RunnerResult<()> {
    let config_path = match args.config {
        Some(path) => path,
        None => default_config_path(),
    };
    let config = load_config(&config_path)?;
    if config.network != Network::Mainnet {
        return Err(RunnerError::MainnetRequired {
            configured: config.network,
        }
        .into());
    }
    let backend = backend_kind(config.backend);

    // Spawn the chain-data service directly. Unlike zainod's Indexer wrapper,
    // this path creates no gRPC, JSON-RPC, metrics, or other network listener.
    let service_config = NodeBackedIndexerServiceConfig::try_from(config)?;
    let mut service = NodeBackedIndexerService::spawn(service_config).await?;
    let scan_result = scan_fixed_snapshot(
        &service,
        args.progress_interval,
        args.fetch_concurrency,
        args.target_height,
        args.target_hash.as_deref(),
    )
    .await;
    service.close();
    let scan = scan_result?;
    let provenance = CaptureProvenance::new(
        backend,
        scan.snapshot_mode,
        scan.serviceable_height,
        scan.selection_mode,
        env!("CARGO_PKG_VERSION"),
        &scan.measurement,
    )?;
    publish_capture(&args.output_dir, &scan.measurement, &provenance)?;
    println!("capture_artifact={}", args.output_dir.display());
    Ok(())
}

const fn backend_kind(backend: BackendType) -> BackendKind {
    match backend {
        BackendType::Direct => BackendKind::Direct,
        BackendType::Rpc => BackendKind::Rpc,
    }
}

async fn scan_fixed_snapshot(
    service: &NodeBackedIndexerService,
    progress_interval: NonZeroU32,
    fetch_concurrency: NonZeroUsize,
    target_height: Option<u32>,
    target_hash: Option<&str>,
) -> RunnerResult<CaptureScan> {
    let subscriber = service.get_subscriber().inner();
    let snapshot = subscriber.indexer.snapshot_nonfinalized_state().await?;
    let snapshot_mode = classify_snapshot(&snapshot)?;
    let serviceable_height = u32::from(*snapshot.max_serviceable_height());
    let (fixed_tip, expected_hash, selection_mode) =
        select_target(serviceable_height, target_height, target_hash)?;
    if let Some(expected_hash) = expected_hash {
        let typed_height = Height::try_from(fixed_tip)
            .map_err(|_| RunnerError::HeightOutOfRange { height: fixed_tip })?;
        let actual_hash = subscriber
            .indexer
            .get_block_hash(&snapshot, typed_height)
            .await?
            .ok_or(RunnerError::MissingCanonicalBlock { height: fixed_tip })?;
        if !actual_hash.to_rpc_hex().eq_ignore_ascii_case(expected_hash) {
            return Err(RunnerError::CheckpointHashMismatch { height: fixed_tip }.into());
        }
    }
    let mut scanner = MainnetCorpusScanner::new();

    eprintln!(
        "corpus_capture_start=mainnet,target_height:{fixed_tip},serviceable_height:{serviceable_height},fetch_concurrency:{}",
        fetch_concurrency.get()
    );
    let fetch_indexer = subscriber.indexer.clone();
    let fetch_snapshot = snapshot.clone();
    reduce_ordered_range(
        0..=fixed_tip,
        fetch_concurrency,
        move |raw_height| {
            let indexer = fetch_indexer.clone();
            let snapshot = fetch_snapshot.clone();
            async move {
                let height = Height::try_from(raw_height)
                    .map_err(|_| RunnerError::HeightOutOfRange { height: raw_height })?;
                let block = indexer
                    .get_indexed_block_by_height(&snapshot, &height)
                    .await?
                    .ok_or(RunnerError::MissingCanonicalBlock { height: raw_height })?;
                Ok::<_, Box<dyn Error + Send + Sync>>(block)
            }
        },
        |raw_height, block| {
            scanner.push(&block)?;

            if raw_height % progress_interval.get() == 0 || raw_height == fixed_tip {
                eprintln!(
                    "corpus_capture_progress=mainnet,current_height:{raw_height},target_height:{fixed_tip}"
                );
            }
            Ok(())
        },
    )
    .await?;

    let measurement = scanner.finish()?;
    measurement.validate()?;
    if measurement.checkpoint().height() != fixed_tip
        || target_hash.is_some_and(|expected_hash| {
            !measurement
                .checkpoint()
                .hash()
                .eq_ignore_ascii_case(expected_hash)
        })
    {
        return Err(RunnerError::MeasuredCheckpointMismatch.into());
    }
    Ok(CaptureScan {
        measurement,
        snapshot_mode,
        serviceable_height,
        selection_mode,
    })
}

/// Fetches a bounded number of items concurrently while reducing them in range order.
async fn reduce_ordered_range<T, E, Fetch, FetchFuture, Reduce>(
    heights: RangeInclusive<u32>,
    concurrency: NonZeroUsize,
    fetch: Fetch,
    mut reduce: Reduce,
) -> Result<(), E>
where
    Fetch: Fn(u32) -> FetchFuture,
    FetchFuture: Future<Output = Result<T, E>>,
    Reduce: FnMut(u32, T) -> Result<(), E>,
{
    let fetched = stream::iter(heights)
        .map(|height| {
            let future = fetch(height);
            async move { future.await.map(|item| (height, item)) }
        })
        .buffered(concurrency.get());
    futures::pin_mut!(fetched);

    while let Some(result) = fetched.next().await {
        let (height, item) = result?;
        reduce(height, item)?;
    }
    Ok(())
}

fn parse_capture_fetch_concurrency(value: &str) -> Result<NonZeroUsize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| "fetch concurrency must be a positive integer".to_owned())?;
    let concurrency = NonZeroUsize::new(parsed)
        .ok_or_else(|| "fetch concurrency must be at least 1".to_owned())?;
    if concurrency.get() > MAX_CAPTURE_FETCH_CONCURRENCY {
        return Err(format!(
            "fetch concurrency must not exceed {MAX_CAPTURE_FETCH_CONCURRENCY}"
        ));
    }
    Ok(concurrency)
}

fn validate_checkpoint_hash(hash: &str) -> Result<(), RunnerError> {
    if hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(RunnerError::InvalidCheckpointHash)
    }
}

fn classify_snapshot(snapshot: &ChainIndexSnapshot) -> Result<SnapshotMode, RunnerError> {
    match snapshot {
        ChainIndexSnapshot::NonFinalizedStateExists { .. } => Ok(SnapshotMode::NonFinalizedState),
        ChainIndexSnapshot::StillSyncingFinalizedState { .. } => {
            Err(RunnerError::SnapshotStillSyncing)
        }
    }
}

fn select_target(
    serviceable_height: u32,
    target_height: Option<u32>,
    target_hash: Option<&str>,
) -> Result<(u32, Option<&str>, SelectionMode), RunnerError> {
    match (target_height, target_hash) {
        (None, None) => Ok((serviceable_height, None, SelectionMode::ServiceableTip)),
        (Some(height), Some(hash)) => {
            validate_checkpoint_hash(hash)?;
            if height > serviceable_height {
                return Err(RunnerError::TargetAboveServiceable {
                    target: height,
                    serviceable: serviceable_height,
                });
            }
            Ok((height, Some(hash), SelectionMode::ExplicitCheckpoint))
        }
        _ => Err(RunnerError::IncompleteCheckpoint),
    }
}

struct CaptureScan {
    measurement: MainnetCorpusMeasurement,
    snapshot_mode: SnapshotMode,
    serviceable_height: u32,
    selection_mode: SelectionMode,
}

#[derive(Debug)]
enum RunnerError {
    MainnetRequired {
        configured: Network,
    },
    HeightOutOfRange {
        height: u32,
    },
    MissingCanonicalBlock {
        height: u32,
    },
    CaptureCheckpointAboveServiceable {
        checkpoint: u32,
        serviceable: u32,
    },
    CaptureCheckpointHashMismatch {
        height: u32,
    },
    #[cfg(feature = "typed-qualification")]
    DeclaredRebuildBudgetMiss {
        declared_seconds: u64,
    },
    #[cfg(feature = "typed-qualification")]
    TimingAttemptRequiresSynchronousDispatch,
    #[cfg(feature = "typed-qualification")]
    TimingAttemptNegative {
        cell_id: String,
    },
    #[cfg(feature = "typed-qualification")]
    TimingAttemptUnexpectedTerminal,
    InsertionFailureBudgetMiss {
        failure_budget_bps: u64,
    },
    #[cfg(feature = "private-service")]
    PrivateProjectionUnavailable,
    #[cfg(feature = "private-service")]
    PrivateRuntimeUnavailable,
    #[cfg(feature = "private-service")]
    PrivateListenerOptInRequired,
    IncompleteCheckpoint,
    InvalidCheckpointHash,
    TargetAboveServiceable {
        target: u32,
        serviceable: u32,
    },
    CheckpointHashMismatch {
        height: u32,
    },
    SnapshotStillSyncing,
    MeasuredCheckpointMismatch,
}

impl fmt::Display for RunnerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MainnetRequired { configured } => write!(
                f,
                "source-backed ORAM tools require a mainnet config; configured network is {configured}"
            ),
            Self::HeightOutOfRange { height } => {
                write!(
                    f,
                    "public block height {height} exceeds Zaino's supported range"
                )
            }
            Self::MissingCanonicalBlock { height } => write!(
                f,
                "fixed canonical snapshot has no indexed block at public height {height}"
            ),
            Self::CaptureCheckpointAboveServiceable {
                checkpoint,
                serviceable,
            } => write!(
                f,
                "capture checkpoint height {checkpoint} exceeds fixed snapshot serviceable height {serviceable}"
            ),
            Self::CaptureCheckpointHashMismatch { height } => write!(
                f,
                "fixed canonical snapshot does not match the capture checkpoint hash at height {height}"
            ),
            #[cfg(feature = "typed-qualification")]
            Self::DeclaredRebuildBudgetMiss { declared_seconds } => write!(
                f,
                "fresh-worker rebuild exceeded the declared {declared_seconds}-second allocation-through-readiness budget; the valid negative artifact was published"
            ),
            #[cfg(feature = "typed-qualification")]
            Self::TimingAttemptRequiresSynchronousDispatch => f.write_str(
                "timing run-cell must be dispatched before constructing the asynchronous runtime",
            ),
            #[cfg(feature = "typed-qualification")]
            Self::TimingAttemptNegative { cell_id } => write!(
                f,
                "timing cell {cell_id} retained a valid negative terminal record"
            ),
            #[cfg(feature = "typed-qualification")]
            Self::TimingAttemptUnexpectedTerminal => {
                f.write_str("timing run-cell returned an unexpected terminal state")
            }
            Self::InsertionFailureBudgetMiss {
                failure_budget_bps,
            } => write!(
                f,
                "source-bound insertion analysis exceeded the declared {failure_budget_bps}-basis-point sampled failure budget; the valid NO-GO artifact was published"
            ),
            #[cfg(feature = "private-service")]
            Self::PrivateProjectionUnavailable => f.write_str(
                "the sized projection could not be built from the canonical finalized chain",
            ),
            #[cfg(feature = "private-service")]
            Self::PrivateRuntimeUnavailable => {
                f.write_str("the private-query runtime could not be composed or refreshed")
            }
            #[cfg(feature = "private-service")]
            Self::PrivateListenerOptInRequired => f.write_str(
                "private listener refused: pass --allow-qualification-backend to acknowledge that the qualification-only backend provides no physical obliviousness",
            ),
            Self::IncompleteCheckpoint => {
                f.write_str("target height and target hash must be supplied together")
            }
            Self::InvalidCheckpointHash => {
                f.write_str("target hash must contain exactly 64 hexadecimal characters")
            }
            Self::TargetAboveServiceable {
                target,
                serviceable,
            } => write!(
                f,
                "target height {target} exceeds fixed snapshot serviceable height {serviceable}"
            ),
            Self::CheckpointHashMismatch { height } => write!(
                f,
                "target hash does not match the fixed canonical block at height {height}"
            ),
            Self::SnapshotStillSyncing => f.write_str(
                "corpus capture requires an indexed non-finalized snapshot; the service is still syncing finalized state",
            ),
            Self::MeasuredCheckpointMismatch => f.write_str(
                "completed corpus measurement does not match the preverified public checkpoint",
            ),
        }
    }
}

impl Error for RunnerError {}

#[cfg(test)]
mod tests {
    use super::*;
    use blake2::{Blake2s256, Digest};
    use std::{
        collections::BTreeMap,
        collections::BTreeSet,
        ffi::OsString,
        fs,
        path::Path,
        sync::{Arc, Mutex},
        task::Poll,
    };

    use crate::corpus_artifact::typed_test_measurement;

    #[cfg(feature = "private-service")]
    #[test]
    fn private_listener_requires_explicit_qualification_backend_opt_in() {
        let error = require_private_listener_opt_in(false)
            .expect_err("the private listener is gated off by default");
        assert_eq!(
            error.to_string(),
            "private listener refused: pass --allow-qualification-backend to acknowledge that the qualification-only backend provides no physical obliviousness"
        );
        assert!(require_private_listener_opt_in(true).is_ok());
    }

    #[derive(Debug, PartialEq, Eq, serde::Serialize)]
    struct OrderedFetchFixture {
        height: u32,
        payload: [u8; 4],
    }

    fn valid_args() -> [&'static str; 7] {
        [
            "zainod-oram",
            "corpus",
            "capture",
            "--config",
            "/tmp/zainod.toml",
            "--output-dir",
            "/tmp/oram-capture",
        ]
    }

    fn valid_sizing_args() -> Vec<&'static str> {
        vec![
            "zainod-oram",
            "corpus",
            "size",
            "--input-dir",
            "/tmp/oram-capture",
            "--output-dir",
            "/tmp/oram-sizing",
            "--growth-horizon-years",
            "2",
            "--annual-growth-bps",
            "1000",
            "--directory-capacity",
            "8",
            "--directory-admission-limit",
            "6",
            "--event-capacity",
            "16",
            "--event-admission-limit",
            "12",
            "--max-events-per-address",
            "8",
            "--position-map-entry-bytes",
            "4",
            "--backend-expansion-bps",
            "20000",
            "--tdx-memory-bytes",
            "1000000",
            "--required-headroom-bps",
            "3000",
        ]
    }

    fn valid_sizing_validation_args() -> [&'static str; 7] {
        [
            "zainod-oram",
            "corpus",
            "validate-sizing",
            "--capture-dir",
            "/tmp/oram-capture",
            "--sizing-dir",
            "/tmp/oram-sizing",
        ]
    }

    async fn collect_ordered_fetch_fixture(
        concurrency: NonZeroUsize,
    ) -> RunnerResult<(Vec<OrderedFetchFixture>, Vec<u32>)> {
        const FINAL_HEIGHT: u32 = 7;

        let completion_order = Arc::new(Mutex::new(Vec::new()));
        let fetch_completion_order = Arc::clone(&completion_order);
        let mut reduced = Vec::new();
        reduce_ordered_range(
            0..=FINAL_HEIGHT,
            concurrency,
            move |height| {
                let completion_order = Arc::clone(&fetch_completion_order);
                async move {
                    let mut remaining_polls = FINAL_HEIGHT - height;
                    futures::future::poll_fn(move |context| {
                        if remaining_polls == 0 {
                            Poll::Ready(())
                        } else {
                            remaining_polls -= 1;
                            context.waker().wake_by_ref();
                            Poll::Pending
                        }
                    })
                    .await;
                    completion_order
                        .lock()
                        .expect("fixture completion-order mutex poisoned")
                        .push(height);
                    Ok::<_, Box<dyn Error + Send + Sync>>(OrderedFetchFixture {
                        height,
                        payload: height.to_le_bytes(),
                    })
                }
            },
            |height, item| {
                assert_eq!(item.height, height);
                reduced.push(item);
                Ok(())
            },
        )
        .await?;

        let completion_order = completion_order
            .lock()
            .expect("fixture completion-order mutex poisoned")
            .clone();
        Ok((reduced, completion_order))
    }

    #[cfg(feature = "typed-qualification")]
    fn valid_release_create_args() -> [&'static str; 19] {
        [
            "zainod-oram",
            "release",
            "create-receipt",
            "--source-revision",
            "0123456789abcdef0123456789abcdef01234567",
            "--source-archive",
            "/tmp/source.tar",
            "--cargo-lock",
            "/tmp/Cargo.lock",
            "--rust-toolchain",
            "/tmp/rust-toolchain.toml",
            "--dockerfile",
            "/tmp/Dockerfile.deterministic",
            "--binary",
            "/tmp/build-a/zainod-oram",
            "--reproducible-binary",
            "/tmp/build-b/zainod-oram",
            "--output",
            "/tmp/release-receipt.json",
        ]
    }

    #[cfg(feature = "typed-qualification")]
    #[test]
    fn release_cli_exposes_only_fixed_receipt_inputs() -> Result<(), clap::Error> {
        let cli = Cli::try_parse_from(valid_release_create_args())?;
        let args = match cli.command {
            Command::Release(command) => match command.command {
                ReleaseSubcommand::CreateReceipt(args) => args,
                ReleaseSubcommand::VerifyReceipt(_) => {
                    panic!("create arguments parsed as receipt verification")
                }
            },
            Command::Corpus(_) => panic!("release arguments parsed as corpus"),
            Command::Qualification(_) => panic!("release arguments parsed as qualification"),
            #[cfg(feature = "private-service")]
            Command::Private(_) => panic!("release arguments parsed as private"),
        };
        assert_eq!(
            args.source_revision,
            "0123456789abcdef0123456789abcdef01234567"
        );
        assert_eq!(args.binary, PathBuf::from("/tmp/build-a/zainod-oram"));
        assert_eq!(
            args.reproducible_binary,
            PathBuf::from("/tmp/build-b/zainod-oram")
        );
        assert_eq!(args.output, PathBuf::from("/tmp/release-receipt.json"));

        for (rejected, value) in [
            ("--target", "custom"),
            ("--profile", "debug"),
            ("--features", "custom"),
            ("--rustflags", "custom"),
            ("--source-date-epoch", "2"),
        ] {
            let mut command = valid_release_create_args().to_vec();
            command.extend([rejected, value]);
            assert!(Cli::try_parse_from(command).is_err());
        }

        let verify = Cli::try_parse_from([
            "zainod-oram",
            "release",
            "verify-receipt",
            "--receipt",
            "/tmp/release-receipt.json",
        ])?;
        match verify.command {
            Command::Release(command) => match command.command {
                ReleaseSubcommand::VerifyReceipt(args) => {
                    assert_eq!(args.receipt, PathBuf::from("/tmp/release-receipt.json"));
                }
                ReleaseSubcommand::CreateReceipt(_) => {
                    panic!("verification arguments parsed as receipt creation")
                }
            },
            Command::Corpus(_) => panic!("release arguments parsed as corpus"),
            Command::Qualification(_) => panic!("release arguments parsed as qualification"),
            #[cfg(feature = "private-service")]
            Command::Private(_) => panic!("release arguments parsed as private"),
        }
        Ok(())
    }

    fn snapshot_directory(directory: &Path) -> Result<BTreeMap<OsString, Vec<u8>>, std::io::Error> {
        fs::read_dir(directory)?
            .map(|entry| {
                let entry = entry?;
                let name = entry.file_name();
                let bytes = fs::read(entry.path())?;
                Ok((name, bytes))
            })
            .collect()
    }

    #[cfg(feature = "typed-qualification")]
    fn publish_target_load_inputs(parent: &Path) -> RunnerResult<(PathBuf, PathBuf)> {
        let capture_dir = parent.join("target-load-capture");
        let sizing_dir = parent.join("target-load-sizing");
        let measurement = typed_test_measurement()?;
        let provenance = CaptureProvenance::new(
            BackendKind::Rpc,
            SnapshotMode::NonFinalizedState,
            0,
            SelectionMode::ServiceableTip,
            "test-runner",
            &measurement,
        )?;
        publish_capture(&capture_dir, &measurement, &provenance)?;
        let capture = load_capture(&capture_dir)?;
        let model = MainnetSizingModel::new(0, 0, 64, 48, 128, 96, 3, 4, 20_000, 1_000_000, 3_000)?;
        let qualification = capture.measurement().apply_model(&model)?;
        publish_sizing(&sizing_dir, &capture, &qualification, "test-runner")?;
        Ok((capture_dir, sizing_dir))
    }

    #[cfg(feature = "typed-qualification")]
    fn valid_qualification_args() -> [&'static str; 5] {
        [
            "zainod-oram",
            "qualification",
            "run",
            "--output-dir",
            "/tmp/oram-qualification",
        ]
    }

    #[cfg(feature = "typed-qualification")]
    fn valid_stress_qualification_args(
        profile: &'static str,
        output_dir: &'static str,
    ) -> [&'static str; 7] {
        [
            "zainod-oram",
            "qualification",
            "stress",
            "--profile",
            profile,
            "--output-dir",
            output_dir,
        ]
    }

    #[cfg(feature = "typed-qualification")]
    fn valid_target_load_args() -> [&'static str; 11] {
        [
            "zainod-oram",
            "qualification",
            "target-load",
            "--profile",
            "builder-foundation-v1",
            "--capture-dir",
            "/tmp/oram-capture",
            "--sizing-dir",
            "/tmp/oram-sizing",
            "--output-dir",
            "/tmp/oram-target-load",
        ]
    }

    #[cfg(feature = "typed-qualification")]
    fn valid_cold_rebuild_args() -> [&'static str; 17] {
        [
            "zainod-oram",
            "qualification",
            "cold-rebuild",
            "--profile",
            "source-bound-builder-v1",
            "--config",
            "/tmp/zainod.toml",
            "--capture-dir",
            "/tmp/oram-capture",
            "--sizing-dir",
            "/tmp/oram-sizing",
            "--declared-rebuild-budget-seconds",
            "3600",
            "--output-dir",
            "/tmp/oram-cold-rebuild",
            "--progress-interval",
            "5000",
        ]
    }

    #[cfg(feature = "typed-qualification")]
    fn valid_timing_manifest_create_args() -> [&'static str; 10] {
        [
            "zainod-oram",
            "qualification",
            "timing",
            "create-manifest",
            "--request",
            "/tmp/timing-manifest-request.json",
            "--release-receipt",
            "/tmp/release-receipt.json",
            "--output-dir",
            "/tmp/timing-manifest",
        ]
    }

    #[cfg(feature = "typed-qualification")]
    fn valid_timing_manifest_verify_args() -> [&'static str; 10] {
        [
            "zainod-oram",
            "qualification",
            "timing",
            "verify-manifest",
            "--manifest-dir",
            "/tmp/timing-manifest",
            "--release-receipt",
            "/tmp/release-receipt.json",
            "--expected-manifest-blake2s256",
            "1111111111111111111111111111111111111111111111111111111111111111",
        ]
    }

    #[cfg(feature = "typed-qualification")]
    fn valid_timing_manifest_inspect_args() -> [&'static str; 8] {
        [
            "zainod-oram",
            "qualification",
            "timing",
            "inspect-manifest",
            "--manifest-dir",
            "/tmp/timing-manifest",
            "--expected-manifest-blake2s256",
            "1111111111111111111111111111111111111111111111111111111111111111",
        ]
    }

    #[cfg(feature = "typed-qualification")]
    fn valid_timing_run_cell_args() -> [&'static str; 12] {
        [
            "zainod-oram",
            "qualification",
            "timing",
            "run-cell",
            "--manifest-dir",
            "/tmp/timing-manifest",
            "--release-receipt",
            "/tmp/release-receipt.json",
            "--expected-manifest-blake2s256",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "--ledger-dir",
            "/tmp/timing-ledger",
        ]
    }

    #[cfg(feature = "typed-qualification")]
    fn valid_timing_inspect_ledger_args() -> [&'static str; 10] {
        [
            "zainod-oram",
            "qualification",
            "timing",
            "inspect-ledger",
            "--manifest-dir",
            "/tmp/timing-manifest",
            "--expected-manifest-blake2s256",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "--ledger-dir",
            "/tmp/timing-ledger",
        ]
    }

    #[cfg(feature = "typed-qualification")]
    fn valid_timing_seal_dangling_args() -> [&'static str; 10] {
        [
            "zainod-oram",
            "qualification",
            "timing",
            "seal-dangling",
            "--manifest-dir",
            "/tmp/timing-manifest",
            "--expected-manifest-blake2s256",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "--ledger-dir",
            "/tmp/timing-ledger",
        ]
    }

    fn valid_insertion_bound_args() -> [&'static str; 17] {
        [
            "zainod-oram",
            "qualification",
            "insertion-bound",
            "--profile",
            "current-four-probe-v1",
            "--config",
            "/tmp/zainod.toml",
            "--capture-dir",
            "/tmp/oram-capture",
            "--sizing-dir",
            "/tmp/oram-sizing",
            "--failure-budget-bps",
            "1250",
            "--output-dir",
            "/tmp/oram-insertion-bound",
            "--progress-interval",
            "5000",
        ]
    }

    fn valid_hybrid_sizing_args() -> [&'static str; 15] {
        [
            "zainod-oram",
            "qualification",
            "hybrid-sizing",
            "--profile",
            "live-utxo-base-delta-v1",
            "--config",
            "/tmp/zainod.toml",
            "--capture-dir",
            "/tmp/oram-capture",
            "--sizing-dir",
            "/tmp/oram-sizing",
            "--output-dir",
            "/tmp/oram-hybrid-sizing",
            "--progress-interval",
            "5000",
        ]
    }

    #[cfg(feature = "typed-qualification")]
    fn valid_fixed_page_capacity_args() -> [&'static str; 7] {
        [
            "zainod-oram",
            "qualification",
            "fixed-page-capacity",
            "--hybrid-sizing-dir",
            "/tmp/oram-hybrid-sizing",
            "--expected-hybrid-sizing-blake2s256",
            "2c44f5dcdf851a12053cd8e684c4f97f202f4ff88e49102ad6232b984a746828",
        ]
    }

    fn parsed_corpus(cli: Cli) -> CorpusCommand {
        match cli.command {
            Command::Corpus(command) => command,
            #[cfg(feature = "typed-qualification")]
            Command::Release(_) => panic!("release arguments parsed as corpus"),
            Command::Qualification(_) => panic!("qualification arguments parsed as corpus"),
            #[cfg(feature = "private-service")]
            Command::Private(_) => panic!("corpus arguments parsed as private"),
        }
    }

    fn parsed_insertion_bound(cli: Cli) -> QualificationInsertionBoundArgs {
        match cli.command {
            Command::Qualification(command) => match command.command {
                QualificationSubcommand::InsertionBound(args) => args,
                #[cfg(feature = "typed-qualification")]
                QualificationSubcommand::Run(_)
                | QualificationSubcommand::Stress(_)
                | QualificationSubcommand::TargetLoad(_)
                | QualificationSubcommand::ColdRebuild(_)
                | QualificationSubcommand::FixedPageCapacity(_)
                | QualificationSubcommand::Timing(_) => {
                    panic!("insertion-bound arguments parsed as another qualification command")
                }
                QualificationSubcommand::HybridSizing(_) => {
                    panic!("hybrid-sizing arguments parsed as insertion-bound")
                }
            },
            Command::Corpus(_) => panic!("insertion-bound arguments parsed as corpus"),
            #[cfg(feature = "typed-qualification")]
            Command::Release(_) => panic!("insertion-bound arguments parsed as release"),
            #[cfg(feature = "private-service")]
            Command::Private(_) => panic!("insertion-bound arguments parsed as private"),
        }
    }

    fn parsed_hybrid_sizing(cli: Cli) -> QualificationHybridSizingArgs {
        match cli.command {
            Command::Qualification(command) => match command.command {
                QualificationSubcommand::HybridSizing(args) => args,
                #[cfg(feature = "typed-qualification")]
                QualificationSubcommand::Run(_)
                | QualificationSubcommand::Stress(_)
                | QualificationSubcommand::TargetLoad(_)
                | QualificationSubcommand::ColdRebuild(_)
                | QualificationSubcommand::FixedPageCapacity(_)
                | QualificationSubcommand::Timing(_)
                | QualificationSubcommand::InsertionBound(_) => {
                    panic!("hybrid-sizing arguments parsed as another qualification command")
                }
                #[cfg(not(feature = "typed-qualification"))]
                QualificationSubcommand::InsertionBound(_) => {
                    panic!("hybrid-sizing arguments parsed as insertion-bound")
                }
            },
            Command::Corpus(_) => panic!("hybrid-sizing arguments parsed as corpus"),
            #[cfg(feature = "typed-qualification")]
            Command::Release(_) => panic!("hybrid-sizing arguments parsed as release"),
            #[cfg(feature = "private-service")]
            Command::Private(_) => panic!("hybrid-sizing arguments parsed as private"),
        }
    }

    #[cfg(feature = "typed-qualification")]
    fn parsed_stress_qualification(cli: Cli) -> QualificationStressArgs {
        match cli.command {
            Command::Qualification(command) => match command.command {
                QualificationSubcommand::Stress(args) => args,
                QualificationSubcommand::Run(_) => {
                    panic!("fixed qualification arguments parsed as stress")
                }
                QualificationSubcommand::TargetLoad(_) => {
                    panic!("target-load arguments parsed as stress")
                }
                QualificationSubcommand::ColdRebuild(_) => {
                    panic!("cold-rebuild arguments parsed as stress")
                }
                QualificationSubcommand::Timing(_) => {
                    panic!("timing arguments parsed as stress")
                }
                QualificationSubcommand::InsertionBound(_) => {
                    panic!("insertion-bound arguments parsed as stress")
                }
                QualificationSubcommand::HybridSizing(_) => {
                    panic!("hybrid-sizing arguments parsed as stress")
                }
                QualificationSubcommand::FixedPageCapacity(_) => {
                    panic!("fixed-page-capacity arguments parsed as stress")
                }
            },
            Command::Corpus(_) => panic!("stress arguments parsed as corpus"),
            Command::Release(_) => panic!("stress arguments parsed as release"),
            #[cfg(feature = "private-service")]
            Command::Private(_) => panic!("stress arguments parsed as private"),
        }
    }

    #[cfg(feature = "typed-qualification")]
    #[test]
    fn qualification_cli_exposes_only_the_fixed_scenario_output() -> Result<(), clap::Error> {
        let cli = Cli::try_parse_from(valid_qualification_args())?;
        let args = match cli.command {
            Command::Qualification(command) => match command.command {
                QualificationSubcommand::Run(args) => args,
                QualificationSubcommand::Stress(_) => {
                    panic!("stress arguments parsed as fixed qualification")
                }
                QualificationSubcommand::TargetLoad(_) => {
                    panic!("target-load arguments parsed as fixed qualification")
                }
                QualificationSubcommand::ColdRebuild(_) => {
                    panic!("cold-rebuild arguments parsed as fixed qualification")
                }
                QualificationSubcommand::Timing(_) => {
                    panic!("timing arguments parsed as fixed qualification")
                }
                QualificationSubcommand::InsertionBound(_) => {
                    panic!("insertion-bound arguments parsed as fixed qualification")
                }
                QualificationSubcommand::HybridSizing(_) => {
                    panic!("hybrid-sizing arguments parsed as fixed qualification")
                }
                QualificationSubcommand::FixedPageCapacity(_) => {
                    panic!("fixed-page-capacity arguments parsed as fixed qualification")
                }
            },
            Command::Corpus(_) => panic!("qualification arguments parsed as corpus"),
            Command::Release(_) => panic!("qualification arguments parsed as release"),
            #[cfg(feature = "private-service")]
            Command::Private(_) => panic!("qualification arguments parsed as private"),
        };
        assert_eq!(args.output_dir, PathBuf::from("/tmp/oram-qualification"));

        for rejected in ["--config", "--directory-capacity", "--target-height"] {
            let mut args = valid_qualification_args().to_vec();
            args.extend([rejected, "8"]);
            assert!(Cli::try_parse_from(args).is_err());
        }
        Ok(())
    }

    #[cfg(feature = "typed-qualification")]
    #[test]
    fn timing_manifest_cli_requires_only_predeclared_inputs() -> Result<(), clap::Error> {
        let create = Cli::try_parse_from(valid_timing_manifest_create_args())?;
        match create.command {
            Command::Qualification(command) => match command.command {
                QualificationSubcommand::Timing(command) => match command.command {
                    QualificationTimingSubcommand::Create(args) => {
                        assert_eq!(
                            args.request,
                            PathBuf::from("/tmp/timing-manifest-request.json")
                        );
                        assert_eq!(
                            args.release_receipt,
                            PathBuf::from("/tmp/release-receipt.json")
                        );
                        assert_eq!(args.output_dir, PathBuf::from("/tmp/timing-manifest"));
                    }
                    QualificationTimingSubcommand::Verify(_) => {
                        panic!("manifest creation arguments parsed as verification")
                    }
                    QualificationTimingSubcommand::Inspect(_) => {
                        panic!("manifest creation arguments parsed as retained inspection")
                    }
                    QualificationTimingSubcommand::RunCell(_)
                    | QualificationTimingSubcommand::InspectLedger(_)
                    | QualificationTimingSubcommand::SealDangling(_) => {
                        panic!("manifest creation arguments parsed as attempt-ledger command")
                    }
                },
                _ => panic!("timing manifest arguments parsed as another qualification command"),
            },
            _ => panic!("timing manifest arguments parsed as another top-level command"),
        }

        for required in ["--request", "--release-receipt", "--output-dir"] {
            let mut command = valid_timing_manifest_create_args().to_vec();
            let index = command
                .iter()
                .position(|argument| *argument == required)
                .expect("required timing manifest argument is present");
            command.drain(index..=index + 1);
            assert!(Cli::try_parse_from(command).is_err());
        }
        for (rejected, value) in [
            ("--pairs", "500"),
            ("--warmup-pairs", "50"),
            ("--mode", "hit-miss"),
            ("--directory-capacity", "1024"),
            ("--directory-initial-occupancy", "16"),
            ("--event-capacity", "1024"),
            ("--event-initial-occupancy", "16"),
            ("--seed", "1"),
            ("--mean-bound-nanos", "1000"),
            ("--cdf-distance-bound", "0.1"),
            ("--max-load-average-1m", "1.0"),
            ("--max-competing-processes", "0"),
            ("--max-runqueue-wait-ratio", "0.01"),
            ("--host-identity", "/tmp/host.json"),
            ("--output", "/tmp/timing-v3.json"),
            ("--config", "/tmp/zainod.toml"),
        ] {
            let mut command = valid_timing_manifest_create_args().to_vec();
            command.extend([rejected, value]);
            assert!(Cli::try_parse_from(command).is_err());
        }

        let verify = Cli::try_parse_from(valid_timing_manifest_verify_args())?;
        match verify.command {
            Command::Qualification(command) => match command.command {
                QualificationSubcommand::Timing(command) => match command.command {
                    QualificationTimingSubcommand::Verify(args) => {
                        assert_eq!(args.manifest_dir, PathBuf::from("/tmp/timing-manifest"));
                        assert_eq!(
                            args.release_receipt,
                            PathBuf::from("/tmp/release-receipt.json")
                        );
                        assert_eq!(
                            args.expected_manifest_blake2s256,
                            "1111111111111111111111111111111111111111111111111111111111111111"
                        );
                    }
                    QualificationTimingSubcommand::Create(_) => {
                        panic!("manifest verification arguments parsed as creation")
                    }
                    QualificationTimingSubcommand::Inspect(_) => {
                        panic!("manifest verification arguments parsed as retained inspection")
                    }
                    QualificationTimingSubcommand::RunCell(_)
                    | QualificationTimingSubcommand::InspectLedger(_)
                    | QualificationTimingSubcommand::SealDangling(_) => {
                        panic!("manifest verification arguments parsed as attempt-ledger command")
                    }
                },
                _ => panic!("timing manifest arguments parsed as another qualification command"),
            },
            _ => panic!("timing manifest arguments parsed as another top-level command"),
        }

        for required in [
            "--manifest-dir",
            "--release-receipt",
            "--expected-manifest-blake2s256",
        ] {
            let mut command = valid_timing_manifest_verify_args().to_vec();
            let index = command
                .iter()
                .position(|argument| *argument == required)
                .expect("required timing manifest verification argument is present");
            command.drain(index..=index + 1);
            assert!(Cli::try_parse_from(command).is_err());
        }

        let inspect = Cli::try_parse_from(valid_timing_manifest_inspect_args())?;
        match inspect.command {
            Command::Qualification(command) => match command.command {
                QualificationSubcommand::Timing(command) => match command.command {
                    QualificationTimingSubcommand::Inspect(args) => {
                        assert_eq!(args.manifest_dir, PathBuf::from("/tmp/timing-manifest"));
                        assert_eq!(
                            args.expected_manifest_blake2s256,
                            "1111111111111111111111111111111111111111111111111111111111111111"
                        );
                    }
                    QualificationTimingSubcommand::Create(_)
                    | QualificationTimingSubcommand::Verify(_) => {
                        panic!("retained inspection arguments parsed as execution admission")
                    }
                    QualificationTimingSubcommand::RunCell(_)
                    | QualificationTimingSubcommand::InspectLedger(_)
                    | QualificationTimingSubcommand::SealDangling(_) => {
                        panic!("retained inspection arguments parsed as attempt-ledger command")
                    }
                },
                _ => panic!("timing manifest arguments parsed as another qualification command"),
            },
            _ => panic!("timing manifest arguments parsed as another top-level command"),
        }
        for required in ["--manifest-dir", "--expected-manifest-blake2s256"] {
            let mut command = valid_timing_manifest_inspect_args().to_vec();
            let index = command
                .iter()
                .position(|argument| *argument == required)
                .expect("required timing manifest inspection argument is present");
            command.drain(index..=index + 1);
            assert!(Cli::try_parse_from(command).is_err());
        }
        Ok(())
    }

    #[cfg(feature = "typed-qualification")]
    #[test]
    fn timing_attempt_cli_is_manifest_driven_and_run_cell_is_sync_dispatched(
    ) -> Result<(), clap::Error> {
        let run_cell = Cli::try_parse_from(valid_timing_run_cell_args())?;
        match classify_runner_dispatch(run_cell) {
            RunnerDispatch::TimingCell(args) => {
                assert_eq!(args.manifest_dir, PathBuf::from("/tmp/timing-manifest"));
                assert_eq!(
                    args.release_receipt,
                    PathBuf::from("/tmp/release-receipt.json")
                );
                assert_eq!(
                    args.expected_manifest_blake2s256,
                    "1111111111111111111111111111111111111111111111111111111111111111"
                );
                assert_eq!(args.ledger_dir, PathBuf::from("/tmp/timing-ledger"));
            }
            RunnerDispatch::Async(_) => {
                panic!("timing run-cell arguments were routed through Tokio")
            }
        }
        for required in [
            "--manifest-dir",
            "--release-receipt",
            "--expected-manifest-blake2s256",
            "--ledger-dir",
        ] {
            let mut command = valid_timing_run_cell_args().to_vec();
            let index = command
                .iter()
                .position(|argument| *argument == required)
                .expect("required timing run-cell argument is present");
            command.drain(index..=index + 1);
            assert!(Cli::try_parse_from(command).is_err());
        }

        let inspect = Cli::try_parse_from(valid_timing_inspect_ledger_args())?;
        match classify_runner_dispatch(inspect) {
            RunnerDispatch::Async(Cli {
                command:
                    Command::Qualification(QualificationCommand {
                        command:
                            QualificationSubcommand::Timing(QualificationTimingCommand {
                                command: QualificationTimingSubcommand::InspectLedger(args),
                            }),
                    }),
            }) => {
                assert_eq!(args.manifest_dir, PathBuf::from("/tmp/timing-manifest"));
                assert_eq!(args.ledger_dir, PathBuf::from("/tmp/timing-ledger"));
                assert_eq!(args.expected_head_sequence, None);
                assert_eq!(args.expected_head_blake2s256, None);
            }
            _ => panic!("timing inspect-ledger arguments parsed as another command"),
        }

        let mut witnessed = valid_timing_inspect_ledger_args().to_vec();
        witnessed.extend([
            "--expected-head-sequence",
            "9",
            "--expected-head-blake2s256",
            "2222222222222222222222222222222222222222222222222222222222222222",
        ]);
        assert!(Cli::try_parse_from(witnessed).is_ok());

        for incomplete_witness in [
            ["--expected-head-sequence", "9"],
            [
                "--expected-head-blake2s256",
                "2222222222222222222222222222222222222222222222222222222222222222",
            ],
        ] {
            let mut command = valid_timing_inspect_ledger_args().to_vec();
            command.extend(incomplete_witness);
            assert!(Cli::try_parse_from(command).is_err());
        }

        let seal = Cli::try_parse_from(valid_timing_seal_dangling_args())?;
        match classify_runner_dispatch(seal) {
            RunnerDispatch::Async(Cli {
                command:
                    Command::Qualification(QualificationCommand {
                        command:
                            QualificationSubcommand::Timing(QualificationTimingCommand {
                                command: QualificationTimingSubcommand::SealDangling(args),
                            }),
                    }),
            }) => {
                assert_eq!(args.manifest_dir, PathBuf::from("/tmp/timing-manifest"));
                assert_eq!(args.ledger_dir, PathBuf::from("/tmp/timing-ledger"));
            }
            _ => panic!("timing seal-dangling arguments parsed as another command"),
        }

        let ordinary = Cli::try_parse_from(valid_args())?;
        assert!(matches!(
            classify_runner_dispatch(ordinary),
            RunnerDispatch::Async(_)
        ));
        Ok(())
    }

    #[cfg(feature = "typed-qualification")]
    #[test]
    fn stress_qualification_cli_exposes_only_a_named_profile_and_output() -> Result<(), clap::Error>
    {
        let smoke = parsed_stress_qualification(Cli::try_parse_from(
            valid_stress_qualification_args("smoke-v1", "/tmp/oram-stress-qualification"),
        )?);
        assert_eq!(smoke.profile, StressQualificationProfileArg::SmokeV1);
        assert_eq!(
            smoke.output_dir,
            PathBuf::from("/tmp/oram-stress-qualification")
        );

        let full_map =
            parsed_stress_qualification(Cli::try_parse_from(valid_stress_qualification_args(
                "full-map-saturation-v1",
                "/tmp/oram-full-map-saturation",
            ))?);
        assert_eq!(
            full_map.profile,
            StressQualificationProfileArg::FullMapSaturationV1
        );
        assert_eq!(
            full_map.output_dir,
            PathBuf::from("/tmp/oram-full-map-saturation")
        );

        for profile in ["smoke-v1", "full-map-saturation-v1"] {
            for (rejected, value) in [
                ("--operations", "10"),
                ("--command-count", "10"),
                ("--iterations", "10"),
                ("--concurrency", "2"),
                ("--seed", "1"),
                ("--directory-capacity", "8"),
                ("--directory-admission-limit", "6"),
                ("--event-capacity", "16"),
                ("--event-admission-limit", "12"),
                ("--max-events-per-address", "8"),
                ("--queue-capacity", "1"),
                ("--target-height", "1"),
                ("--target-hash", "11"),
                ("--config", "/tmp/zainod.toml"),
            ] {
                let mut command =
                    valid_stress_qualification_args(profile, "/tmp/oram-stress-qualification")
                        .to_vec();
                command.extend([rejected, value]);
                assert!(Cli::try_parse_from(command).is_err());
            }
        }

        let missing_profile = [
            "zainod-oram",
            "qualification",
            "stress",
            "--output-dir",
            "/tmp/oram-stress-qualification",
        ];
        assert!(Cli::try_parse_from(missing_profile).is_err());

        let mut unknown_profile =
            valid_stress_qualification_args("smoke-v1", "/tmp/oram-stress-qualification");
        unknown_profile[4] = "custom";
        assert!(Cli::try_parse_from(unknown_profile).is_err());
        Ok(())
    }

    #[cfg(feature = "typed-qualification")]
    #[test]
    fn target_load_cli_requires_only_named_profile_and_source_bound_artifacts(
    ) -> Result<(), clap::Error> {
        let cli = Cli::try_parse_from(valid_target_load_args())?;
        let args = match cli.command {
            Command::Qualification(command) => match command.command {
                QualificationSubcommand::TargetLoad(args) => args,
                QualificationSubcommand::Run(_)
                | QualificationSubcommand::Stress(_)
                | QualificationSubcommand::ColdRebuild(_)
                | QualificationSubcommand::Timing(_)
                | QualificationSubcommand::InsertionBound(_)
                | QualificationSubcommand::HybridSizing(_)
                | QualificationSubcommand::FixedPageCapacity(_) => {
                    panic!("target-load arguments parsed as another qualification command")
                }
            },
            Command::Corpus(_) => panic!("target-load arguments parsed as corpus"),
            Command::Release(_) => panic!("target-load arguments parsed as release"),
            #[cfg(feature = "private-service")]
            Command::Private(_) => panic!("target-load arguments parsed as private"),
        };
        assert_eq!(args.profile, TargetLoadProfileArg::BuilderFoundationV1);
        assert_eq!(args.capture_dir, PathBuf::from("/tmp/oram-capture"));
        assert_eq!(args.sizing_dir, PathBuf::from("/tmp/oram-sizing"));
        assert_eq!(args.output_dir, PathBuf::from("/tmp/oram-target-load"));

        for (rejected, value) in [
            ("--operations", "10"),
            ("--concurrency", "2"),
            ("--seed", "1"),
            ("--directory-capacity", "64"),
            ("--event-capacity", "128"),
            ("--queue-capacity", "1"),
            ("--config", "/tmp/zainod.toml"),
        ] {
            let mut command = valid_target_load_args().to_vec();
            command.extend([rejected, value]);
            assert!(Cli::try_parse_from(command).is_err());
        }
        Ok(())
    }

    #[cfg(feature = "typed-qualification")]
    #[test]
    fn cold_rebuild_cli_requires_source_config_lineage_budget_output_and_progress(
    ) -> Result<(), clap::Error> {
        let cli = Cli::try_parse_from(valid_cold_rebuild_args())?;
        let args = match cli.command {
            Command::Qualification(command) => match command.command {
                QualificationSubcommand::ColdRebuild(args) => args,
                QualificationSubcommand::Run(_)
                | QualificationSubcommand::Stress(_)
                | QualificationSubcommand::TargetLoad(_)
                | QualificationSubcommand::Timing(_)
                | QualificationSubcommand::InsertionBound(_)
                | QualificationSubcommand::HybridSizing(_)
                | QualificationSubcommand::FixedPageCapacity(_) => {
                    panic!("cold-rebuild arguments parsed as another qualification command")
                }
            },
            Command::Corpus(_) => panic!("cold-rebuild arguments parsed as corpus"),
            Command::Release(_) => panic!("cold-rebuild arguments parsed as release"),
            #[cfg(feature = "private-service")]
            Command::Private(_) => panic!("cold-rebuild arguments parsed as private"),
        };
        assert_eq!(args.profile, ColdRebuildProfileArg::SourceBoundBuilderV1);
        assert_eq!(args.config, PathBuf::from("/tmp/zainod.toml"));
        assert_eq!(args.capture_dir, PathBuf::from("/tmp/oram-capture"));
        assert_eq!(args.sizing_dir, PathBuf::from("/tmp/oram-sizing"));
        assert_eq!(args.declared_rebuild_budget_seconds.get(), 3_600);
        assert_eq!(args.output_dir, PathBuf::from("/tmp/oram-cold-rebuild"));
        assert_eq!(args.progress_interval.get(), 5_000);

        for required in [
            "--profile",
            "--config",
            "--capture-dir",
            "--sizing-dir",
            "--declared-rebuild-budget-seconds",
            "--output-dir",
            "--progress-interval",
        ] {
            let mut missing = valid_cold_rebuild_args().to_vec();
            let Some(index) = missing.iter().position(|value| *value == required) else {
                panic!("valid cold-rebuild fixture must contain {required}");
            };
            missing.drain(index..=index + 1);
            assert!(Cli::try_parse_from(missing).is_err());
        }

        for zero_option in ["--declared-rebuild-budget-seconds", "--progress-interval"] {
            let mut zero = valid_cold_rebuild_args();
            let Some(index) = zero.iter().position(|value| *value == zero_option) else {
                panic!("valid cold-rebuild fixture must contain {zero_option}");
            };
            zero[index + 1] = "0";
            assert!(Cli::try_parse_from(zero).is_err());
        }

        let mut unknown_profile = valid_cold_rebuild_args();
        unknown_profile[4] = "custom";
        assert!(Cli::try_parse_from(unknown_profile).is_err());
        Ok(())
    }

    #[test]
    fn insertion_bound_cli_requires_source_config_lineage_budget_output_and_progress(
    ) -> Result<(), clap::Error> {
        let args = parsed_insertion_bound(Cli::try_parse_from(valid_insertion_bound_args())?);
        assert_eq!(args.profile, InsertionBoundProfileArg::CurrentFourProbeV1);
        assert_eq!(args.config, PathBuf::from("/tmp/zainod.toml"));
        assert_eq!(args.capture_dir, PathBuf::from("/tmp/oram-capture"));
        assert_eq!(args.sizing_dir, PathBuf::from("/tmp/oram-sizing"));
        assert_eq!(args.failure_budget_bps, 1_250);
        assert_eq!(args.output_dir, PathBuf::from("/tmp/oram-insertion-bound"));
        assert_eq!(args.progress_interval.get(), 5_000);

        for required in [
            "--profile",
            "--config",
            "--capture-dir",
            "--sizing-dir",
            "--failure-budget-bps",
            "--output-dir",
            "--progress-interval",
        ] {
            let mut missing = valid_insertion_bound_args().to_vec();
            let Some(index) = missing.iter().position(|value| *value == required) else {
                panic!("valid insertion-bound fixture must contain {required}");
            };
            missing.drain(index..=index + 1);
            assert!(Cli::try_parse_from(missing).is_err());
        }

        for (budget, expected) in [("0", 0), ("10000", 10_000)] {
            let mut boundary = valid_insertion_bound_args();
            boundary[12] = budget;
            let args = parsed_insertion_bound(Cli::try_parse_from(boundary)?);
            assert_eq!(args.failure_budget_bps, expected);
        }

        let mut over_budget = valid_insertion_bound_args();
        over_budget[12] = "10001";
        assert!(Cli::try_parse_from(over_budget).is_err());

        let mut zero_progress = valid_insertion_bound_args();
        zero_progress[16] = "0";
        assert!(Cli::try_parse_from(zero_progress).is_err());

        let mut unknown_profile = valid_insertion_bound_args();
        unknown_profile[4] = "custom";
        assert!(Cli::try_parse_from(unknown_profile).is_err());

        for (rejected, value) in [
            ("--seed", "1"),
            ("--directory-capacity", "64"),
            ("--probe-count", "4"),
            ("--tdx-memory-bytes", "1000000"),
        ] {
            let mut command = valid_insertion_bound_args().to_vec();
            command.extend([rejected, value]);
            assert!(Cli::try_parse_from(command).is_err());
        }
        Ok(())
    }

    #[test]
    fn hybrid_sizing_cli_requires_profile_source_lineage_output_and_progress(
    ) -> Result<(), clap::Error> {
        let args = parsed_hybrid_sizing(Cli::try_parse_from(valid_hybrid_sizing_args())?);
        assert_eq!(args.profile, HybridSizingProfileArg::LiveUtxoBaseDeltaV1);
        assert_eq!(args.config, PathBuf::from("/tmp/zainod.toml"));
        assert_eq!(args.capture_dir, PathBuf::from("/tmp/oram-capture"));
        assert_eq!(args.sizing_dir, PathBuf::from("/tmp/oram-sizing"));
        assert_eq!(args.output_dir, PathBuf::from("/tmp/oram-hybrid-sizing"));
        assert_eq!(args.progress_interval.get(), 5_000);

        let mut growth_profile = valid_hybrid_sizing_args();
        growth_profile[4] = "live-utxo-base-delta-growth-v2";
        let growth_args = parsed_hybrid_sizing(Cli::try_parse_from(growth_profile)?);
        assert_eq!(
            growth_args.profile,
            HybridSizingProfileArg::LiveUtxoBaseDeltaGrowthV2
        );

        for required in [
            "--profile",
            "--config",
            "--capture-dir",
            "--sizing-dir",
            "--output-dir",
            "--progress-interval",
        ] {
            let mut missing = valid_hybrid_sizing_args().to_vec();
            let Some(index) = missing.iter().position(|value| *value == required) else {
                panic!("valid hybrid-sizing fixture must contain {required}");
            };
            missing.drain(index..=index + 1);
            assert!(Cli::try_parse_from(missing).is_err());
        }

        let mut zero_progress = valid_hybrid_sizing_args();
        zero_progress[14] = "0";
        assert!(Cli::try_parse_from(zero_progress).is_err());

        let mut unknown_profile = valid_hybrid_sizing_args();
        unknown_profile[4] = "custom";
        assert!(Cli::try_parse_from(unknown_profile).is_err());

        for (rejected, value) in [
            ("--failure-budget-bps", "1000"),
            ("--directory-capacity", "64"),
            ("--tdx-memory-bytes", "1000000"),
        ] {
            let mut command = valid_hybrid_sizing_args().to_vec();
            command.extend([rejected, value]);
            assert!(Cli::try_parse_from(command).is_err());
        }
        Ok(())
    }

    #[cfg(feature = "typed-qualification")]
    #[test]
    fn fixed_page_capacity_cli_requires_bundle_and_external_digest() -> Result<(), clap::Error> {
        let cli = Cli::try_parse_from(valid_fixed_page_capacity_args())?;
        let args = match cli.command {
            Command::Qualification(QualificationCommand {
                command: QualificationSubcommand::FixedPageCapacity(args),
            }) => args,
            _ => panic!("fixed-page-capacity arguments parsed as another command"),
        };
        assert_eq!(
            args.hybrid_sizing_dir,
            PathBuf::from("/tmp/oram-hybrid-sizing")
        );
        assert_eq!(
            args.expected_hybrid_sizing_blake2s256,
            "2c44f5dcdf851a12053cd8e684c4f97f202f4ff88e49102ad6232b984a746828"
        );

        for required in ["--hybrid-sizing-dir", "--expected-hybrid-sizing-blake2s256"] {
            let mut missing = valid_fixed_page_capacity_args().to_vec();
            let Some(index) = missing.iter().position(|value| *value == required) else {
                panic!("valid fixed-page-capacity fixture must contain {required}");
            };
            missing.drain(index..=index + 1);
            assert!(Cli::try_parse_from(missing).is_err());
        }
        Ok(())
    }

    #[cfg(not(feature = "typed-qualification"))]
    #[test]
    fn insertion_bound_cli_remains_available_without_typed_qualification() -> Result<(), clap::Error>
    {
        let args = parsed_insertion_bound(Cli::try_parse_from(valid_insertion_bound_args())?);
        assert_eq!(args.failure_budget_bps, 1_250);
        Ok(())
    }

    #[cfg(not(feature = "typed-qualification"))]
    #[test]
    fn hybrid_sizing_cli_remains_available_without_typed_qualification() -> Result<(), clap::Error>
    {
        let args = parsed_hybrid_sizing(Cli::try_parse_from(valid_hybrid_sizing_args())?);
        assert_eq!(args.profile, HybridSizingProfileArg::LiveUtxoBaseDeltaV1);
        Ok(())
    }

    #[cfg(not(feature = "typed-qualification"))]
    #[test]
    fn target_load_cli_is_absent_without_typed_qualification() {
        assert!(Cli::try_parse_from([
            "zainod-oram",
            "qualification",
            "target-load",
            "--profile",
            "builder-foundation-v1",
            "--capture-dir",
            "/tmp/oram-capture",
            "--sizing-dir",
            "/tmp/oram-sizing",
            "--output-dir",
            "/tmp/oram-target-load",
        ])
        .is_err());
    }

    #[cfg(not(feature = "typed-qualification"))]
    #[test]
    fn cold_rebuild_cli_is_absent_without_typed_qualification() {
        assert!(Cli::try_parse_from([
            "zainod-oram",
            "qualification",
            "cold-rebuild",
            "--profile",
            "source-bound-builder-v1",
            "--config",
            "/tmp/zainod.toml",
            "--capture-dir",
            "/tmp/oram-capture",
            "--sizing-dir",
            "/tmp/oram-sizing",
            "--declared-rebuild-budget-seconds",
            "3600",
            "--output-dir",
            "/tmp/oram-cold-rebuild",
            "--progress-interval",
            "5000",
        ])
        .is_err());
    }

    #[cfg(all(
        feature = "typed-qualification",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    #[tokio::test]
    async fn qualification_dispatch_publishes_exactly_three_files() -> RunnerResult<()> {
        let parent = tempfile::tempdir()?;
        let output_dir = parent.path().join("qualification");

        run(Cli {
            command: Command::Qualification(QualificationCommand {
                command: QualificationSubcommand::Run(QualificationRunArgs {
                    output_dir: output_dir.clone(),
                }),
            }),
        })
        .await?;

        let names = fs::read_dir(output_dir)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<BTreeSet<_>, _>>()?;
        assert_eq!(
            names,
            BTreeSet::from([
                OsString::from("provenance.json"),
                OsString::from("qualification.json"),
                OsString::from("qualification.txt"),
            ])
        );
        Ok(())
    }

    #[cfg(all(
        feature = "typed-qualification",
        not(all(target_os = "linux", target_arch = "x86_64"))
    ))]
    #[tokio::test]
    async fn qualification_dispatch_fails_without_publishing_on_unsupported_hosts(
    ) -> RunnerResult<()> {
        let parent = tempfile::tempdir()?;
        let output_dir = parent.path().join("qualification");

        let result = run(Cli {
            command: Command::Qualification(QualificationCommand {
                command: QualificationSubcommand::Run(QualificationRunArgs {
                    output_dir: output_dir.clone(),
                }),
            }),
        })
        .await;

        assert!(result.is_err());
        assert!(!output_dir.exists());
        Ok(())
    }

    #[cfg(all(
        feature = "typed-qualification",
        not(all(target_os = "linux", target_arch = "x86_64"))
    ))]
    #[tokio::test]
    async fn stress_profile_dispatch_fails_without_publishing_on_unsupported_hosts(
    ) -> RunnerResult<()> {
        let parent = tempfile::tempdir()?;
        for (profile, output_name) in [
            (
                StressQualificationProfileArg::SmokeV1,
                "stress-qualification",
            ),
            (
                StressQualificationProfileArg::FullMapSaturationV1,
                "full-map-saturation",
            ),
        ] {
            let output_dir = parent.path().join(output_name);
            let result = run(Cli {
                command: Command::Qualification(QualificationCommand {
                    command: QualificationSubcommand::Stress(QualificationStressArgs {
                        profile,
                        output_dir: output_dir.clone(),
                    }),
                }),
            })
            .await;

            assert!(result.is_err());
            assert!(!output_dir.exists());
        }
        Ok(())
    }

    #[cfg(all(
        feature = "typed-qualification",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    #[tokio::test]
    async fn full_map_saturation_dispatch_publishes_exactly_three_files() -> RunnerResult<()> {
        let parent = tempfile::tempdir()?;
        let output_dir = parent.path().join("full-map-saturation");

        run(Cli {
            command: Command::Qualification(QualificationCommand {
                command: QualificationSubcommand::Stress(QualificationStressArgs {
                    profile: StressQualificationProfileArg::FullMapSaturationV1,
                    output_dir: output_dir.clone(),
                }),
            }),
        })
        .await?;

        let names = fs::read_dir(output_dir)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<BTreeSet<_>, _>>()?;
        assert_eq!(
            names,
            BTreeSet::from([
                OsString::from("full-map-saturation.json"),
                OsString::from("full-map-saturation.txt"),
                OsString::from("provenance.json"),
            ])
        );
        Ok(())
    }

    #[cfg(all(
        feature = "typed-qualification",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    #[tokio::test]
    async fn target_load_dispatch_consumes_source_bound_sizing_and_publishes_three_files(
    ) -> RunnerResult<()> {
        let parent = tempfile::tempdir()?;
        let (capture_dir, sizing_dir) = publish_target_load_inputs(parent.path())?;
        let output_dir = parent.path().join("target-load");

        run(Cli {
            command: Command::Qualification(QualificationCommand {
                command: QualificationSubcommand::TargetLoad(QualificationTargetLoadArgs {
                    profile: TargetLoadProfileArg::BuilderFoundationV1,
                    capture_dir,
                    sizing_dir,
                    output_dir: output_dir.clone(),
                }),
            }),
        })
        .await?;

        let names = fs::read_dir(output_dir)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<BTreeSet<_>, _>>()?;
        assert_eq!(
            names,
            BTreeSet::from([
                OsString::from("provenance.json"),
                OsString::from("target-load.json"),
                OsString::from("target-load.txt"),
            ])
        );
        Ok(())
    }

    #[cfg(all(
        feature = "typed-qualification",
        not(all(target_os = "linux", target_arch = "x86_64"))
    ))]
    #[tokio::test]
    async fn target_load_dispatch_fails_without_publication_on_unsupported_hosts(
    ) -> RunnerResult<()> {
        let parent = tempfile::tempdir()?;
        let (capture_dir, sizing_dir) = publish_target_load_inputs(parent.path())?;
        let output_dir = parent.path().join("target-load");

        let result = run(Cli {
            command: Command::Qualification(QualificationCommand {
                command: QualificationSubcommand::TargetLoad(QualificationTargetLoadArgs {
                    profile: TargetLoadProfileArg::BuilderFoundationV1,
                    capture_dir,
                    sizing_dir,
                    output_dir: output_dir.clone(),
                }),
            }),
        })
        .await;

        assert!(result.is_err());
        assert!(!output_dir.exists());
        Ok(())
    }

    #[test]
    fn corpus_capture_cli_has_no_sizing_parameters() -> Result<(), clap::Error> {
        let cli = Cli::try_parse_from(valid_args())?;
        let command = parsed_corpus(cli);
        let args = match command.command {
            CorpusSubcommand::Capture(args) => args,
            CorpusSubcommand::Size(_) => panic!("capture arguments parsed as sizing arguments"),
            CorpusSubcommand::ValidateSizing(_) => {
                panic!("capture arguments parsed as sizing-validation arguments")
            }
        };

        assert_eq!(args.output_dir, PathBuf::from("/tmp/oram-capture"));
        assert_eq!(args.progress_interval.get(), 10_000);
        assert_eq!(args.fetch_concurrency.get(), 1);
        assert_eq!(args.target_height, None);
        assert_eq!(args.target_hash, None);

        let mut pipelined = valid_args().to_vec();
        pipelined.extend(["--fetch-concurrency", "8"]);
        let args = match parsed_corpus(Cli::try_parse_from(pipelined)?).command {
            CorpusSubcommand::Capture(args) => args,
            CorpusSubcommand::Size(_) => panic!("capture arguments parsed as sizing arguments"),
            CorpusSubcommand::ValidateSizing(_) => {
                panic!("capture arguments parsed as sizing-validation arguments")
            }
        };
        assert_eq!(args.fetch_concurrency.get(), 8);

        for invalid in ["0", "33"] {
            let mut command = valid_args().to_vec();
            command.extend(["--fetch-concurrency", invalid]);
            assert!(Cli::try_parse_from(command).is_err());
        }
        Ok(())
    }

    #[tokio::test]
    async fn ordered_pipelining_preserves_fixture_bytes_and_digest() -> RunnerResult<()> {
        let sequential_concurrency =
            NonZeroUsize::new(1).expect("fixture sequential concurrency is nonzero");
        let pipelined_concurrency =
            NonZeroUsize::new(4).expect("fixture pipelined concurrency is nonzero");
        let (sequential, sequential_completion_order) =
            collect_ordered_fetch_fixture(sequential_concurrency).await?;
        let (pipelined, pipelined_completion_order) =
            collect_ordered_fetch_fixture(pipelined_concurrency).await?;

        assert_eq!(sequential_completion_order, (0..=7).collect::<Vec<_>>());
        assert_ne!(pipelined_completion_order, sequential_completion_order);
        assert_eq!(
            pipelined.iter().map(|item| item.height).collect::<Vec<_>>(),
            (0..=7).collect::<Vec<_>>()
        );

        let sequential_bytes = serde_json::to_vec(&sequential)?;
        let pipelined_bytes = serde_json::to_vec(&pipelined)?;
        assert_eq!(pipelined_bytes, sequential_bytes);
        assert_eq!(
            Blake2s256::digest(&pipelined_bytes),
            Blake2s256::digest(&sequential_bytes)
        );
        Ok(())
    }

    #[test]
    fn corpus_size_cli_is_offline_and_requires_every_explicit_model_input(
    ) -> Result<(), Box<dyn Error>> {
        let cli = Cli::try_parse_from(valid_sizing_args())?;
        let command = parsed_corpus(cli);
        let args = match command.command {
            CorpusSubcommand::Size(args) => args,
            CorpusSubcommand::Capture(_) => {
                panic!("sizing arguments parsed as capture arguments")
            }
            CorpusSubcommand::ValidateSizing(_) => {
                panic!("sizing arguments parsed as sizing-validation arguments")
            }
        };

        assert_eq!(args.input_dir, PathBuf::from("/tmp/oram-capture"));
        assert_eq!(args.output_dir, PathBuf::from("/tmp/oram-sizing"));
        assert_eq!(args.growth_horizon_years, 2);
        assert_eq!(args.annual_growth_bps, 1_000);
        assert_eq!(args.directory_capacity, 8);
        assert_eq!(args.directory_admission_limit, 6);
        assert_eq!(args.event_capacity, 16);
        assert_eq!(args.event_admission_limit, 12);
        assert_eq!(args.max_events_per_address, 8);
        assert_eq!(args.position_map_entry_bytes, 4);
        assert_eq!(args.backend_expansion_bps, 20_000);
        assert_eq!(args.tdx_memory_bytes, 1_000_000);
        assert_eq!(args.required_headroom_bps, 3_000);
        args.model()?.validate()?;

        for required in [
            "--growth-horizon-years",
            "--annual-growth-bps",
            "--directory-capacity",
            "--directory-admission-limit",
            "--event-capacity",
            "--event-admission-limit",
            "--max-events-per-address",
            "--position-map-entry-bytes",
            "--backend-expansion-bps",
            "--tdx-memory-bytes",
            "--required-headroom-bps",
        ] {
            let mut missing_model_input = valid_sizing_args();
            let Some(index) = missing_model_input
                .iter()
                .position(|value| *value == required)
            else {
                panic!("valid sizing fixture must contain {required}");
            };
            missing_model_input.drain(index..=index + 1);
            assert!(Cli::try_parse_from(missing_model_input).is_err());
        }

        let mut node_option = valid_sizing_args();
        node_option.extend(["--config", "/tmp/zainod.toml"]);
        assert!(Cli::try_parse_from(node_option).is_err());
        Ok(())
    }

    #[test]
    fn corpus_validate_sizing_cli_accepts_only_the_two_input_directories() -> Result<(), clap::Error>
    {
        let cli = Cli::try_parse_from(valid_sizing_validation_args())?;
        let command = parsed_corpus(cli);
        let args = match command.command {
            CorpusSubcommand::ValidateSizing(args) => args,
            CorpusSubcommand::Capture(_) => {
                panic!("sizing-validation arguments parsed as capture arguments")
            }
            CorpusSubcommand::Size(_) => {
                panic!("sizing-validation arguments parsed as sizing arguments")
            }
        };

        assert_eq!(args.capture_dir, PathBuf::from("/tmp/oram-capture"));
        assert_eq!(args.sizing_dir, PathBuf::from("/tmp/oram-sizing"));

        for (rejected, value) in [
            ("--output-dir", "/tmp/new-artifact"),
            ("--config", "/tmp/zainod.toml"),
            ("--directory-capacity", "8"),
            ("--queue-capacity", "1"),
        ] {
            let mut command = valid_sizing_validation_args().to_vec();
            command.extend([rejected, value]);
            assert!(Cli::try_parse_from(command).is_err());
        }
        Ok(())
    }

    #[tokio::test]
    async fn corpus_size_dispatch_executes_end_to_end_without_node_or_config_state(
    ) -> RunnerResult<()> {
        let parent = tempfile::tempdir()?;
        let input_dir = parent.path().join("capture");
        let output_dir = parent.path().join("sizing");
        let measurement = typed_test_measurement()?;
        let provenance = CaptureProvenance::new(
            BackendKind::Rpc,
            SnapshotMode::NonFinalizedState,
            0,
            SelectionMode::ServiceableTip,
            "test-runner",
            &measurement,
        )?;
        publish_capture(&input_dir, &measurement, &provenance)?;

        run(Cli {
            command: Command::Corpus(CorpusCommand {
                command: CorpusSubcommand::Size(CorpusSizeArgs {
                    input_dir,
                    output_dir: output_dir.clone(),
                    growth_horizon_years: 2,
                    annual_growth_bps: 1_000,
                    directory_capacity: 8,
                    directory_admission_limit: 6,
                    event_capacity: 16,
                    event_admission_limit: 12,
                    max_events_per_address: 8,
                    position_map_entry_bytes: 4,
                    backend_expansion_bps: 20_000,
                    tdx_memory_bytes: 1_000_000,
                    required_headroom_bps: 3_000,
                }),
            }),
        })
        .await?;

        let names = fs::read_dir(output_dir)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<BTreeSet<_>, _>>()?;
        assert_eq!(
            names,
            BTreeSet::from([
                OsString::from("provenance.json"),
                OsString::from("qualification.json"),
                OsString::from("qualification.txt"),
            ])
        );
        Ok(())
    }

    #[tokio::test]
    async fn corpus_validate_sizing_dispatch_is_read_only() -> RunnerResult<()> {
        let parent = tempfile::tempdir()?;
        let capture_dir = parent.path().join("capture");
        let sizing_dir = parent.path().join("sizing");
        let measurement = typed_test_measurement()?;
        let provenance = CaptureProvenance::new(
            BackendKind::Rpc,
            SnapshotMode::NonFinalizedState,
            0,
            SelectionMode::ServiceableTip,
            "test-runner",
            &measurement,
        )?;
        publish_capture(&capture_dir, &measurement, &provenance)?;
        let capture = load_capture(&capture_dir)?;
        let model =
            MainnetSizingModel::new(2, 1_000, 8, 6, 16, 12, 8, 4, 20_000, 1_000_000, 3_000)?;
        let qualification = capture.measurement().apply_model(&model)?;
        publish_sizing(&sizing_dir, &capture, &qualification, "test-runner")?;

        let sizing = load_sizing(&sizing_dir, &capture)?;
        let summary = format_validated_sizing_summary(&sizing);
        assert_eq!(
            summary,
            "sizing_input=valid,measurement_blake2s256:f98ee2710b69837cb9fc53c69a82153e80f67e89a237279fc757c4e34e953ed0,qualification_blake2s256:6b65372684f65d095dfce09419c574bb5e73e4f4528559166e1d1e9d3b23ff66,directory_capacity:8,directory_admission_limit:6,event_capacity:16,event_admission_limit:12,max_events_per_address:8"
        );
        for forbidden in [
            "capture_dir",
            "checkpoint_hash",
            "config",
            "latency",
            "output_dir",
            "queue",
            "runner_version",
            "seed",
            "sizing_dir",
            "target_os",
            "transaction",
        ] {
            assert!(!summary.contains(forbidden));
        }

        let capture_before = snapshot_directory(&capture_dir)?;
        let sizing_before = snapshot_directory(&sizing_dir)?;

        run(Cli {
            command: Command::Corpus(CorpusCommand {
                command: CorpusSubcommand::ValidateSizing(CorpusValidateSizingArgs {
                    capture_dir: capture_dir.clone(),
                    sizing_dir: sizing_dir.clone(),
                }),
            }),
        })
        .await?;

        assert_eq!(snapshot_directory(&capture_dir)?, capture_before);
        assert_eq!(snapshot_directory(&sizing_dir)?, sizing_before);
        Ok(())
    }

    #[test]
    fn corpus_cli_rejects_zero_progress_interval() {
        let mut args = valid_args().to_vec();
        args.extend(["--progress-interval", "0"]);

        assert!(Cli::try_parse_from(args).is_err());
    }

    #[test]
    fn explicit_checkpoint_requires_height_and_hash_together() {
        let mut height_only = valid_args().to_vec();
        height_only.extend(["--target-height", "123"]);
        assert!(Cli::try_parse_from(height_only).is_err());

        let mut hash_only = valid_args().to_vec();
        let target_hash = "11".repeat(32);
        hash_only.extend(["--target-hash", &target_hash]);
        assert!(Cli::try_parse_from(hash_only).is_err());
    }

    #[test]
    fn checkpoint_hash_validation_accepts_only_exact_hex() {
        assert!(validate_checkpoint_hash(&"aB".repeat(32)).is_ok());
        assert!(validate_checkpoint_hash(&"ab".repeat(31)).is_err());
        assert!(validate_checkpoint_hash(&"gg".repeat(32)).is_err());
    }

    #[test]
    fn target_selection_covers_tip_explicit_and_rejected_inputs() {
        assert!(matches!(
            select_target(200, None, None),
            Ok((200, None, SelectionMode::ServiceableTip))
        ));
        let hash = "11".repeat(32);
        assert!(matches!(
            select_target(200, Some(123), Some(&hash)),
            Ok((123, Some(_), SelectionMode::ExplicitCheckpoint))
        ));
        assert!(matches!(
            select_target(200, Some(201), Some(&hash)),
            Err(RunnerError::TargetAboveServiceable {
                target: 201,
                serviceable: 200,
            })
        ));
        assert!(matches!(
            select_target(200, Some(123), None),
            Err(RunnerError::IncompleteCheckpoint)
        ));
    }

    #[test]
    fn syncing_snapshot_is_rejected_before_scanning() -> Result<(), RunnerError> {
        let height =
            Height::try_from(0).map_err(|_| RunnerError::HeightOutOfRange { height: 0 })?;
        let snapshot = ChainIndexSnapshot::StillSyncingFinalizedState {
            validator_finalized_height: height,
        };

        assert!(matches!(
            classify_snapshot(&snapshot),
            Err(RunnerError::SnapshotStillSyncing)
        ));
        Ok(())
    }
}
