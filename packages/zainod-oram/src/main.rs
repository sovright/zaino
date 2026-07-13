//! Non-published one-shot tools for Zaino ORAM research.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

use std::{error::Error, fmt, num::NonZeroU32, path::PathBuf, process::ExitCode};

#[cfg(feature = "typed-qualification")]
use clap::ValueEnum;
use clap::{Args, Parser, Subcommand};
use zaino_common::Network;
#[cfg(feature = "typed-qualification")]
use zaino_oram::{
    run_typed_worker_full_map_saturation, run_typed_worker_qualification,
    run_typed_worker_stress_qualification, TypedWorkerFullMapSaturationProfile,
    TypedWorkerStressProfile,
};
use zaino_oram::{MainnetCorpusMeasurement, MainnetCorpusScanner, MainnetSizingModel};
use zaino_state::{
    chain_index::NonFinalizedSnapshot, ChainIndex, ChainIndexSnapshot, Height,
    NodeBackedIndexerService, NodeBackedIndexerServiceConfig, ZcashService,
};
use zainodlib::{
    cli::default_config_path,
    config::{load_config, BackendType},
};

use crate::corpus_artifact::{
    load_capture, load_sizing, publish_capture, publish_sizing, BackendKind, CaptureProvenance,
    SelectionMode, SnapshotMode, ValidatedSizing,
};
#[cfg(feature = "typed-qualification")]
use crate::full_map_saturation_artifact::publish_full_map_saturation;
#[cfg(feature = "typed-qualification")]
use crate::qualification_artifact::publish_qualification;
#[cfg(feature = "typed-qualification")]
use crate::stress_qualification_artifact::publish_stress_qualification;

mod corpus_artifact;
#[cfg(feature = "typed-qualification")]
mod full_map_saturation_artifact;
#[cfg(feature = "typed-qualification")]
mod qualification_artifact;
#[cfg(feature = "typed-qualification")]
mod stress_qualification_artifact;

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
    /// Exercise the fixed typed-worker correctness scenario without a listener.
    #[cfg(feature = "typed-qualification")]
    Qualification(QualificationCommand),
}

#[cfg(feature = "typed-qualification")]
#[derive(Debug, Args)]
struct QualificationCommand {
    #[command(subcommand)]
    command: QualificationSubcommand,
}

#[cfg(feature = "typed-qualification")]
#[derive(Debug, Subcommand)]
enum QualificationSubcommand {
    /// Run the fixed correctness scenario and publish aggregate evidence.
    Run(QualificationRunArgs),
    /// Run a fixed stress profile and publish aggregate evidence.
    Stress(QualificationStressArgs),
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum StressQualificationProfileArg {
    /// Fixed smoke-level stress qualification profile.
    #[value(name = "smoke-v1")]
    SmokeV1,
    /// Fixed full admitted-map correctness-saturation profile.
    #[value(name = "full-map-saturation-v1")]
    FullMapSaturationV1,
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

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ORAM research runner failed: {error}");
            ExitCode::FAILURE
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
        Command::Qualification(command) => match command.command {
            QualificationSubcommand::Run(args) => run_qualification(args),
            QualificationSubcommand::Stress(args) => run_stress_qualification(args),
        },
    }
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
    use std::{collections::BTreeMap, collections::BTreeSet, ffi::OsString, fs, path::Path};

    use crate::corpus_artifact::typed_test_measurement;

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

    fn parsed_corpus(cli: Cli) -> CorpusCommand {
        match cli.command {
            Command::Corpus(command) => command,
            #[cfg(feature = "typed-qualification")]
            Command::Qualification(_) => panic!("qualification arguments parsed as corpus"),
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
            },
            Command::Corpus(_) => panic!("stress arguments parsed as corpus"),
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
            },
            Command::Corpus(_) => panic!("qualification arguments parsed as corpus"),
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
        assert_eq!(args.target_height, None);
        assert_eq!(args.target_hash, None);
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
