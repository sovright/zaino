//! Non-published one-shot tools for Zaino ORAM research.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

use std::{error::Error, fmt, num::NonZeroU32, path::PathBuf, process::ExitCode};

use clap::{Args, Parser, Subcommand};
use zaino_common::Network;
use zaino_oram::{MainnetCorpusMeasurement, MainnetCorpusScanner};
use zaino_state::{
    chain_index::NonFinalizedSnapshot, ChainIndex, ChainIndexSnapshot, Height,
    NodeBackedIndexerService, NodeBackedIndexerServiceConfig, ZcashService,
};
use zainodlib::{
    cli::default_config_path,
    config::{load_config, BackendType},
};

use crate::corpus_artifact::{
    publish_capture, BackendKind, CaptureProvenance, SelectionMode, SnapshotMode,
};

mod corpus_artifact;

type RunnerResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

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

    /// Public height to capture instead of the snapshot's serviceable tip.
    #[arg(long, requires = "target_hash")]
    target_height: Option<u32>,

    /// RPC-order block hash paired with --target-height.
    #[arg(long, value_name = "HEX", requires = "target_height")]
    target_hash: Option<String>,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ORAM corpus runner failed: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> RunnerResult<()> {
    match cli.command {
        Command::Corpus(command) => match command.command {
            CorpusSubcommand::Capture(args) => run_corpus_capture(args).await,
        },
    }
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
    let backend = match config.backend {
        BackendType::Direct => BackendKind::Direct,
        BackendType::Rpc => BackendKind::Rpc,
    };

    // Spawn the chain-data service directly. Unlike zainod's Indexer wrapper,
    // this path creates no gRPC, JSON-RPC, metrics, or other network listener.
    let service_config = NodeBackedIndexerServiceConfig::try_from(config)?;
    let mut service = NodeBackedIndexerService::spawn(service_config).await?;
    let scan_result = scan_fixed_snapshot(
        &service,
        args.progress_interval,
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

async fn scan_fixed_snapshot(
    service: &NodeBackedIndexerService,
    progress_interval: NonZeroU32,
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
        "corpus_capture_start=mainnet,target_height:{fixed_tip},serviceable_height:{serviceable_height}"
    );
    for raw_height in 0..=fixed_tip {
        let height = Height::try_from(raw_height)
            .map_err(|_| RunnerError::HeightOutOfRange { height: raw_height })?;
        let block = subscriber
            .indexer
            .get_indexed_block_by_height(&snapshot, &height)
            .await?
            .ok_or(RunnerError::MissingCanonicalBlock { height: raw_height })?;
        scanner.push(&block)?;

        if raw_height % progress_interval.get() == 0 || raw_height == fixed_tip {
            eprintln!(
                "corpus_capture_progress=mainnet,current_height:{raw_height},target_height:{fixed_tip}"
            );
        }
    }

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
    MainnetRequired { configured: Network },
    HeightOutOfRange { height: u32 },
    MissingCanonicalBlock { height: u32 },
    IncompleteCheckpoint,
    InvalidCheckpointHash,
    TargetAboveServiceable { target: u32, serviceable: u32 },
    CheckpointHashMismatch { height: u32 },
    SnapshotStillSyncing,
    MeasuredCheckpointMismatch,
}

impl fmt::Display for RunnerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MainnetRequired { configured } => write!(
                f,
                "corpus scans require a mainnet config; configured network is {configured}"
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

    #[test]
    fn corpus_capture_cli_has_no_sizing_parameters() -> Result<(), clap::Error> {
        let cli = Cli::try_parse_from(valid_args())?;
        let Command::Corpus(command) = cli.command;
        let CorpusSubcommand::Capture(args) = command.command;

        assert_eq!(args.output_dir, PathBuf::from("/tmp/oram-capture"));
        assert_eq!(args.progress_interval.get(), 10_000);
        assert_eq!(args.target_height, None);
        assert_eq!(args.target_hash, None);
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
