//! Non-published one-shot tools for Zaino ORAM research.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

use std::{error::Error, fmt, num::NonZeroU32, path::PathBuf, process::ExitCode};

use clap::{Args, Parser, Subcommand};
use zaino_common::Network;
use zaino_oram::{MainnetCorpusModel, MainnetCorpusScanner};
use zaino_state::{
    chain_index::NonFinalizedSnapshot, ChainIndex, Height, NodeBackedIndexerService,
    NodeBackedIndexerServiceConfig, ZcashService,
};
use zainodlib::{cli::default_config_path, config::load_config};

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
    /// Scan one fixed canonical mainnet snapshot into aggregate corpus output.
    Corpus(CorpusArgs),
}

#[derive(Debug, Args)]
struct CorpusArgs {
    /// Zainod TOML config. The config and connected validator must be mainnet.
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Emit aggregate progress every this many public block heights.
    #[arg(long, default_value = "10000")]
    progress_interval: NonZeroU32,

    /// Number of years included in the proportional growth projection.
    #[arg(long)]
    growth_horizon_years: u16,

    /// Projected annual growth in basis points.
    #[arg(long)]
    annual_growth_bps: u64,

    /// Fixed event slots reserved in every logical address page.
    #[arg(long)]
    events_per_page: u64,

    /// Fixed metadata overhead reserved per logical address page.
    #[arg(long)]
    page_overhead_bytes: u64,

    /// Fixed logical address-directory entry width.
    #[arg(long)]
    directory_entry_bytes: u64,

    /// Fixed logical position-map entry width.
    #[arg(long)]
    position_map_entry_bytes: u64,

    /// Modeled backend expansion in basis points; 10,000 means 1x.
    #[arg(long)]
    backend_expansion_bps: u64,

    /// Intended TDX guest memory capacity in bytes.
    #[arg(long)]
    tdx_memory_bytes: u64,

    /// Memory headroom reserved in basis points.
    #[arg(long)]
    required_headroom_bps: u64,
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
        Command::Corpus(args) => run_corpus(args).await,
    }
}

async fn run_corpus(args: CorpusArgs) -> RunnerResult<()> {
    let model = MainnetCorpusModel::new(
        args.growth_horizon_years,
        args.annual_growth_bps,
        args.events_per_page,
        args.page_overhead_bytes,
        args.directory_entry_bytes,
        args.position_map_entry_bytes,
        args.backend_expansion_bps,
        args.tdx_memory_bytes,
        args.required_headroom_bps,
    )?;
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

    // Spawn the chain-data service directly. Unlike zainod's Indexer wrapper,
    // this path creates no gRPC, JSON-RPC, metrics, or other network listener.
    let service_config = NodeBackedIndexerServiceConfig::try_from(config)?;
    let mut service = NodeBackedIndexerService::spawn(service_config).await?;
    let scan_result = scan_fixed_snapshot(&service, model, args.progress_interval).await;
    service.close();
    scan_result
}

async fn scan_fixed_snapshot(
    service: &NodeBackedIndexerService,
    model: MainnetCorpusModel,
    progress_interval: NonZeroU32,
) -> RunnerResult<()> {
    let subscriber = service.get_subscriber().inner();
    let snapshot = subscriber.indexer.snapshot_nonfinalized_state().await?;
    let fixed_tip = u32::from(*snapshot.max_serviceable_height());
    let mut scanner = MainnetCorpusScanner::new(model);

    eprintln!("corpus_scan_start=mainnet,fixed_tip_height:{fixed_tip}");
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
                "corpus_scan_progress=mainnet,current_height:{raw_height},fixed_tip_height:{fixed_tip}"
            );
        }
    }

    let report = scanner.finish()?;
    print!("{report}");
    Ok(())
}

#[derive(Debug)]
enum RunnerError {
    MainnetRequired { configured: Network },
    HeightOutOfRange { height: u32 },
    MissingCanonicalBlock { height: u32 },
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
        }
    }
}

impl Error for RunnerError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_args() -> [&'static str; 22] {
        [
            "zainod-oram",
            "corpus",
            "--config",
            "/tmp/zainod.toml",
            "--growth-horizon-years",
            "5",
            "--annual-growth-bps",
            "500",
            "--events-per-page",
            "64",
            "--page-overhead-bytes",
            "32",
            "--directory-entry-bytes",
            "64",
            "--position-map-entry-bytes",
            "8",
            "--backend-expansion-bps",
            "20000",
            "--tdx-memory-bytes",
            "68719476736",
            "--required-headroom-bps",
            "3000",
        ]
    }

    #[test]
    fn corpus_cli_requires_explicit_model_parameters() -> Result<(), clap::Error> {
        let cli = Cli::try_parse_from(valid_args())?;
        let Command::Corpus(args) = cli.command;

        assert_eq!(args.growth_horizon_years, 5);
        assert_eq!(args.required_headroom_bps, 3_000);
        assert_eq!(args.progress_interval.get(), 10_000);
        Ok(())
    }

    #[test]
    fn corpus_cli_rejects_zero_progress_interval() {
        let mut args = valid_args().to_vec();
        args.extend(["--progress-interval", "0"]);

        assert!(Cli::try_parse_from(args).is_err());
    }
}
