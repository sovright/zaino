//! Build deterministic Zaino release products with a pinned container toolchain.
//!
//! With no product selection, this preserves the historical `zainod` flow and
//! forwards extra arguments to both container builds. `--product zainod-oram`
//! instead performs two exact-HEAD no-cache binary builds, compares their
//! output, creates and verifies a release receipt, and atomically publishes
//! `build/oram-release/`. Equality is an observation, not proof that the two
//! executions were physically independent.

use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
use rustix::fs::{fsync, open, renameat_with, Mode, OFlags, RenameFlags};
use workbench::{repo_root, run};

const PLATFORM: &str = "linux/amd64";
const IMAGE_REF: &str = "localhost/zainod:deterministic";
const ORAM_PRODUCT: &str = "zainod-oram";
const ORAM_RELEASE_DIRECTORY: &str = "oram-release";
const ORAM_RECEIPT: &str = "release-receipt.json";
const MAX_TEMP_ATTEMPTS: u64 = 128;

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Product {
    Zainod,
    ZainodOram,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BuildRequest {
    product: Product,
    forwarded: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Engine {
    Docker,
    Podman,
}

fn main() {
    run("build-deterministic", build, |()| {})
}

fn build() -> Result<(), Vec<String>> {
    let request = parse_args(env::args().skip(1))?;
    let root = repo_root()?;
    match request.product {
        Product::Zainod => build_zainod(&root, &request.forwarded),
        Product::ZainodOram => build_zainod_oram(&root),
    }
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<BuildRequest, Vec<String>> {
    let args: Vec<String> = args.into_iter().collect();
    let mut product = None;
    let mut forwarded = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let argument = &args[index];
        let product_value = if argument == "--product" {
            index = index.checked_add(1).ok_or_else(|| {
                vec!["argument index overflow while parsing --product".to_owned()]
            })?;
            Some(
                args.get(index)
                    .ok_or_else(|| vec!["--product requires a value".to_owned()])?
                    .as_str(),
            )
        } else {
            argument.strip_prefix("--product=")
        };

        if let Some(value) = product_value {
            if product.is_some() {
                return Err(vec!["--product may be supplied only once".to_owned()]);
            }
            product = Some(parse_product(value)?);
        } else {
            forwarded.push(argument.clone());
        }
        index = index
            .checked_add(1)
            .ok_or_else(|| vec!["argument index overflow".to_owned()])?;
    }

    let product = product.unwrap_or(Product::Zainod);
    if product == Product::ZainodOram && !forwarded.is_empty() {
        return Err(vec![format!(
            "{ORAM_PRODUCT} deterministic builds do not accept forwarded container arguments: {}",
            forwarded.join(" ")
        )]);
    }
    Ok(BuildRequest { product, forwarded })
}

fn parse_product(value: &str) -> Result<Product, Vec<String>> {
    match value {
        "zainod" => Ok(Product::Zainod),
        ORAM_PRODUCT => Ok(Product::ZainodOram),
        other => Err(vec![format!(
            "unsupported product {other:?}; expected `zainod` or `{ORAM_PRODUCT}`"
        )]),
    }
}

fn build_zainod(root: &Path, forwarded: &[String]) -> Result<(), Vec<String>> {
    let dockerfile = root.join("Dockerfile.deterministic");
    let oci_output = root.join("build/oci");
    let engine = select_engine()?;

    fs::create_dir_all(&oci_output)
        .map_err(|error| vec![format!("cannot create {}: {error}", oci_output.display())])?;

    println!("Building runtime image with {}...", engine.binary());
    let oci_tar = oci_output.join("zainod.tar");
    engine.build_runtime_oci(&dockerfile, root, &oci_tar, forwarded)?;

    println!("Extracting binary with {}...", engine.binary());
    engine.build_export(&dockerfile, root, forwarded)
}

fn build_zainod_oram(root: &Path) -> Result<(), Vec<String>> {
    ensure_clean_git_tree(root)?;
    let revision = full_head(root)?;
    let output_directory = root.join("build").join(ORAM_RELEASE_DIRECTORY);
    ensure_path_absent(&output_directory, "ORAM release output")?;
    let engine = select_engine()?;
    let source = TemporarySource::create(root, &revision)?;

    let prepared = prepare_oram_release(root, engine, &source, &revision);
    let cleanup = source.cleanup();
    match (prepared, cleanup) {
        (Ok(stage), Ok(())) => stage.publish(),
        (Err(mut build_errors), Err(cleanup_errors)) => {
            build_errors.extend(cleanup_errors);
            Err(build_errors)
        }
        (Err(build_errors), Ok(())) => Err(build_errors),
        (Ok(_stage), Err(cleanup_errors)) => Err(cleanup_errors),
    }
}

fn prepare_oram_release(
    root: &Path,
    engine: Engine,
    source: &TemporarySource,
    revision: &str,
) -> Result<OutputStage, Vec<String>> {
    let first_output = source.root.join("first-build");
    let second_output = source.root.join("second-build");
    let dockerfile = source.context.join("Dockerfile.deterministic");

    println!("Running no-cache {ORAM_PRODUCT} build (1/2)...");
    engine.build_oram_export(&dockerfile, &source.context, &first_output)?;
    println!("Running no-cache {ORAM_PRODUCT} build (2/2)...");
    engine.build_oram_export(&dockerfile, &source.context, &second_output)?;

    let binary_a = first_output.join(ORAM_PRODUCT);
    let binary_b = second_output.join(ORAM_PRODUCT);
    if !files_equal_streaming(&binary_a, &binary_b).map_err(|error| {
        vec![format!(
            "cannot compare the two no-cache {ORAM_PRODUCT} build outputs: {error}"
        )]
    })? {
        return Err(vec![
            "the two no-cache zainod-oram build outputs differ byte-for-byte".to_owned(),
        ]);
    }

    let receipt = source.root.join(ORAM_RECEIPT);
    let cargo_lock = source.context.join("Cargo.lock");
    let rust_toolchain = source.context.join("rust-toolchain.toml");
    let mut create = create_receipt_command(ReceiptInputs {
        binary_a: &binary_a,
        revision,
        source_archive: &source.archive,
        cargo_lock: &cargo_lock,
        rust_toolchain: &rust_toolchain,
        dockerfile: &dockerfile,
        binary_b: &binary_b,
        output: &receipt,
    });
    run_command(&mut create, "create zainod-oram release receipt")?;

    let mut verify = verify_receipt_command(&binary_b, &receipt);
    run_command(&mut verify, "verify zainod-oram release receipt")?;
    ensure_regular_nonempty_file(&receipt, "release receipt")?;

    OutputStage::prepare(root, &binary_a, &receipt)
}

struct ReceiptInputs<'a> {
    binary_a: &'a Path,
    revision: &'a str,
    source_archive: &'a Path,
    cargo_lock: &'a Path,
    rust_toolchain: &'a Path,
    dockerfile: &'a Path,
    binary_b: &'a Path,
    output: &'a Path,
}

fn create_receipt_command(inputs: ReceiptInputs<'_>) -> Command {
    let mut command = Command::new(inputs.binary_a);
    command
        .args([
            "release",
            "create-receipt",
            "--source-revision",
            inputs.revision,
        ])
        .arg("--source-archive")
        .arg(inputs.source_archive)
        .arg("--cargo-lock")
        .arg(inputs.cargo_lock)
        .arg("--rust-toolchain")
        .arg(inputs.rust_toolchain)
        .arg("--dockerfile")
        .arg(inputs.dockerfile)
        .arg("--binary")
        .arg(inputs.binary_a)
        .arg("--reproducible-binary")
        .arg(inputs.binary_b)
        .arg("--output")
        .arg(inputs.output);
    command
}

fn verify_receipt_command(binary_b: &Path, receipt: &Path) -> Command {
    let mut command = Command::new(binary_b);
    command
        .args(["release", "verify-receipt", "--receipt"])
        .arg(receipt);
    command
}

fn files_equal_streaming(left: &Path, right: &Path) -> io::Result<bool> {
    let left_file = File::open(left)?;
    let right_file = File::open(right)?;
    readers_equal(BufReader::new(left_file), BufReader::new(right_file))
}

fn readers_equal<L: BufRead, R: BufRead>(mut left: L, mut right: R) -> io::Result<bool> {
    loop {
        let (count, equal, both_finished) = {
            let left_buffer = left.fill_buf()?;
            let right_buffer = right.fill_buf()?;
            let count = left_buffer.len().min(right_buffer.len());
            let both_finished = left_buffer.is_empty() && right_buffer.is_empty();
            let one_finished = left_buffer.is_empty() != right_buffer.is_empty();
            let equal = !one_finished && left_buffer[..count] == right_buffer[..count];
            (count, equal, both_finished)
        };
        if both_finished {
            return Ok(true);
        }
        if !equal {
            return Ok(false);
        }
        left.consume(count);
        right.consume(count);
    }
}

struct TemporarySource {
    repo_root: PathBuf,
    root: PathBuf,
    worktree: PathBuf,
    context: PathBuf,
    archive: PathBuf,
    registered_worktree: bool,
    cleaned: bool,
}

impl TemporarySource {
    fn create(repo_root: &Path, revision: &str) -> Result<Self, Vec<String>> {
        let root =
            create_unique_directory(&env::temp_dir(), "zaino-oram-release").map_err(|error| {
                vec![format!(
                    "cannot create temporary release directory: {error}"
                )]
            })?;
        let worktree = root.join("worktree");
        let context = root.join("context");
        let archive = root.join("source.tar");
        let mut source = Self {
            repo_root: repo_root.to_path_buf(),
            root,
            worktree,
            context,
            archive,
            registered_worktree: false,
            cleaned: false,
        };

        match source.setup(revision) {
            Ok(()) => Ok(source),
            Err(mut setup_errors) => {
                if let Err(mut cleanup_errors) = source.cleanup() {
                    setup_errors.append(&mut cleanup_errors);
                }
                Err(setup_errors)
            }
        }
    }

    fn setup(&mut self, revision: &str) -> Result<(), Vec<String>> {
        let mut add = git_worktree_add_command(&self.repo_root, &self.worktree, revision);
        run_command(&mut add, "create detached exact-HEAD worktree")?;
        self.registered_worktree = true;

        let detached_head = full_head(&self.worktree)?;
        if detached_head != revision {
            return Err(vec![format!(
                "detached worktree resolved {detached_head}, expected {revision}"
            )]);
        }

        let mut archive_command = git_archive_command(&self.worktree, &self.archive, revision);
        run_command(&mut archive_command, "create deterministic git archive")?;
        fs::create_dir(&self.context).map_err(|error| {
            vec![format!(
                "cannot create archive build context {}: {error}",
                self.context.display()
            )]
        })?;
        let mut extract = archive_extract_command(&self.archive, &self.context);
        run_command(&mut extract, "extract deterministic build context")?;
        Ok(())
    }

    fn cleanup(mut self) -> Result<(), Vec<String>> {
        let result = self.cleanup_inner();
        // An explicit cleanup failure deliberately leaves the owned worktree in
        // place for manual recovery; Drop must not retry and make that report stale.
        self.cleaned = true;
        result
    }

    fn cleanup_inner(&mut self) -> Result<(), Vec<String>> {
        if self.registered_worktree {
            let mut remove = git_worktree_remove_command(&self.repo_root, &self.worktree);
            if command_succeeded(&mut remove) {
                self.registered_worktree = false;
            } else {
                return Err(vec![format!(
                    "cannot remove owned temporary git worktree {}; it was left in place and must be cleaned manually",
                    self.worktree.display()
                )]);
            }
        }
        remove_directory_if_present(&self.root).map_err(|error| {
            vec![format!(
                "cannot remove temporary release directory {}: {error}",
                self.root.display()
            )]
        })
    }
}

impl Drop for TemporarySource {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.cleanup_inner();
        }
    }
}

struct OutputStage {
    stage: PathBuf,
    destination: PathBuf,
    published: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum AtomicPublishOutcome {
    PublishedAndSynced,
    PublishedButDurabilityUncertain(String),
}

impl OutputStage {
    fn prepare(root: &Path, binary: &Path, receipt: &Path) -> Result<Self, Vec<String>> {
        let parent = root.join("build");
        fs::create_dir_all(&parent).map_err(|error| {
            vec![format!(
                "cannot create release output parent {}: {error}",
                parent.display()
            )]
        })?;
        let destination = parent.join(ORAM_RELEASE_DIRECTORY);
        // Early feedback only; publication enforces no-replace atomically.
        ensure_path_absent(&destination, "ORAM release output")?;
        let stage = create_unique_directory(&parent, ".oram-release.stage").map_err(|error| {
            vec![format!(
                "cannot create release staging directory in {}: {error}",
                parent.display()
            )]
        })?;
        let output = Self {
            stage,
            destination,
            published: false,
        };
        copy_synced(
            binary,
            &output.stage.join(ORAM_PRODUCT),
            "zainod-oram binary",
        )?;
        copy_synced(receipt, &output.stage.join(ORAM_RECEIPT), "release receipt")?;
        sync_directory(&output.stage, "release staging directory")?;
        let mut verify = verify_receipt_command(
            &output.stage.join(ORAM_PRODUCT),
            &output.stage.join(ORAM_RECEIPT),
        );
        run_command(&mut verify, "verify staged zainod-oram release")?;
        Ok(output)
    }

    fn publish(mut self) -> Result<(), Vec<String>> {
        let publication = atomic_publish_directory(&self.stage, &self.destination)?;
        self.published = true;
        let mut verify = verify_receipt_command(
            &self.destination.join(ORAM_PRODUCT),
            &self.destination.join(ORAM_RECEIPT),
        );
        let verification = run_command(&mut verify, "verify published zainod-oram release");
        finish_publication(&self.destination, publication, verification)?;
        println!("oram_release={}", self.destination.display());
        Ok(())
    }
}

fn finish_publication(
    destination: &Path,
    publication: AtomicPublishOutcome,
    verification: Result<(), Vec<String>>,
) -> Result<(), Vec<String>> {
    match (publication, verification) {
        (AtomicPublishOutcome::PublishedAndSynced, Ok(())) => Ok(()),
        (AtomicPublishOutcome::PublishedAndSynced, Err(errors)) => Err(vec![format!(
            "ORAM release is complete and visible at {}, but supplemental final self-verification failed; output was left untouched: {}",
            destination.display(),
            errors.join("; ")
        )]),
        (
            AtomicPublishOutcome::PublishedButDurabilityUncertain(sync_error),
            Ok(()),
        ) => Err(vec![format!(
            "ORAM release is complete and visible at {}, but synchronization of the publication parent descriptor failed and crash durability is uncertain; supplemental final self-verification succeeded and output was left untouched: {sync_error}",
            destination.display()
        )]),
        (
            AtomicPublishOutcome::PublishedButDurabilityUncertain(sync_error),
            Err(verification_errors),
        ) => Err(vec![format!(
            "ORAM release is complete and visible at {}, but synchronization of the publication parent descriptor failed and crash durability is uncertain; supplemental final self-verification also failed and output was left untouched: parent synchronization: {sync_error}; self-verification: {}",
            destination.display(),
            verification_errors.join("; ")
        )]),
    }
}

impl Drop for OutputStage {
    fn drop(&mut self) {
        if !self.published {
            let _ = remove_directory_if_present(&self.stage);
        }
    }
}

fn copy_synced(source: &Path, destination: &Path, label: &str) -> Result<(), Vec<String>> {
    fs::copy(source, destination).map_err(|error| {
        vec![format!(
            "cannot copy {label} from {} to {}: {error}",
            source.display(),
            destination.display()
        )]
    })?;
    File::open(destination)
        .and_then(|file| file.sync_all())
        .map_err(|error| {
            vec![format!(
                "cannot synchronize {label} {}: {error}",
                destination.display()
            )]
        })
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn atomic_publish_directory(
    stage: &Path,
    destination: &Path,
) -> Result<AtomicPublishOutcome, Vec<String>> {
    atomic_publish_directory_with_parent_sync(stage, destination, |parent| fsync(parent))
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn atomic_publish_directory_with_parent_sync<F>(
    stage: &Path,
    destination: &Path,
    sync_parent: F,
) -> Result<AtomicPublishOutcome, Vec<String>>
where
    F: FnOnce(&rustix::fd::OwnedFd) -> rustix::io::Result<()>,
{
    let stage_parent = stage.parent().ok_or_else(|| {
        vec![format!(
            "release staging path has no parent: {}",
            stage.display()
        )]
    })?;
    if destination.parent() != Some(stage_parent) {
        return Err(vec![
            "release staging and destination directories must share one parent".to_owned(),
        ]);
    }
    let stage_name = stage.file_name().ok_or_else(|| {
        vec![format!(
            "release staging path has no filename: {}",
            stage.display()
        )]
    })?;
    let destination_name = destination.file_name().ok_or_else(|| {
        vec![format!(
            "release destination has no filename: {}",
            destination.display()
        )]
    })?;
    let parent = open(
        stage_parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        vec![format!(
            "cannot open release output parent {} without following symlinks: {error}",
            stage_parent.display()
        )]
    })?;
    renameat_with(
        &parent,
        stage_name,
        &parent,
        destination_name,
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        if error == rustix::io::Errno::EXIST {
            vec![format!(
                "ORAM release output already exists at {}; refusing to replace it",
                destination.display()
            )]
        } else {
            vec![format!(
                "cannot atomically publish {} as {} without replacement: {error}",
                stage.display(),
                destination.display()
            )]
        }
    })?;
    match sync_parent(&parent) {
        Ok(()) => Ok(AtomicPublishOutcome::PublishedAndSynced),
        Err(error) => Ok(AtomicPublishOutcome::PublishedButDurabilityUncertain(
            error.to_string(),
        )),
    }
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn atomic_publish_directory(
    _stage: &Path,
    _destination: &Path,
) -> Result<AtomicPublishOutcome, Vec<String>> {
    Err(vec![
        "atomic no-replace ORAM release publication is unsupported on this host".to_owned(),
    ])
}

fn sync_directory(directory: &Path, label: &str) -> Result<(), Vec<String>> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| {
            vec![format!(
                "cannot synchronize {label} {}: {error}",
                directory.display()
            )]
        })
}

fn create_unique_directory(parent: &Path, prefix: &str) -> io::Result<PathBuf> {
    for _ in 0..MAX_TEMP_ATTEMPTS {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!("{prefix}-{}-{id}", std::process::id()));
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "temporary directory name attempts exhausted",
    ))
}

fn remove_directory_if_present(directory: &Path) -> io::Result<()> {
    match fs::remove_dir_all(directory) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn ensure_path_absent(path: &Path, label: &str) -> Result<(), Vec<String>> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(vec![format!(
            "{label} already exists at {}; refusing to replace it",
            path.display()
        )]),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(vec![format!(
            "cannot inspect {label} {}: {error}",
            path.display()
        )]),
    }
}

fn ensure_regular_nonempty_file(path: &Path, label: &str) -> Result<(), Vec<String>> {
    let metadata = fs::metadata(path).map_err(|error| {
        vec![format!(
            "cannot inspect {label} {}: {error}",
            path.display()
        )]
    })?;
    if metadata.is_file() && metadata.len() > 0 {
        Ok(())
    } else {
        Err(vec![format!(
            "{label} {} is not a nonempty regular file",
            path.display()
        )])
    }
}

fn ensure_clean_git_tree(root: &Path) -> Result<(), Vec<String>> {
    let mut command = Command::new("git");
    command.arg("-C").arg(root).args([
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignore-submodules=none",
    ]);
    let output = run_output(&mut command, "inspect git tree status")?;
    let entries = parse_status_entries(&output.stdout);
    if entries.is_empty() {
        Ok(())
    } else {
        Err(vec![format!(
            "{ORAM_PRODUCT} deterministic builds require a completely clean git tree; found {}",
            entries.join(", ")
        )])
    }
}

fn parse_status_entries(output: &[u8]) -> Vec<String> {
    output
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| String::from_utf8_lossy(entry).into_owned())
        .collect()
}

fn full_head(root: &Path) -> Result<String, Vec<String>> {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--verify", "HEAD^{commit}"]);
    let output = run_output(&mut command, "resolve full HEAD revision")?;
    let head = String::from_utf8(output.stdout)
        .map_err(|error| vec![format!("git HEAD output is not UTF-8: {error}")])?;
    parse_full_head(head.trim())
}

fn parse_full_head(head: &str) -> Result<String, Vec<String>> {
    if head.len() == 40
        && head
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(head.to_owned())
    } else {
        Err(vec![format!(
            "git did not return a 40-character lowercase hexadecimal HEAD: {head:?}"
        )])
    }
}

fn git_worktree_add_command(repo_root: &Path, worktree: &Path, revision: &str) -> Command {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(repo_root)
        .args(["worktree", "add", "--detach"])
        .arg(worktree)
        .arg(revision);
    command
}

fn git_worktree_remove_command(repo_root: &Path, worktree: &Path) -> Command {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(repo_root)
        .args(["worktree", "remove", "--force"])
        .arg(worktree);
    command
}

fn git_archive_command(worktree: &Path, archive: &Path, revision: &str) -> Command {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(worktree)
        .args(["archive", "--format=tar", "--output"])
        .arg(archive)
        .arg(revision);
    command
}

fn archive_extract_command(archive: &Path, context: &Path) -> Command {
    let mut command = Command::new("tar");
    command.args(["-xf"]).arg(archive).arg("-C").arg(context);
    command
}

fn run_command(command: &mut Command, description: &str) -> Result<(), Vec<String>> {
    let status = command
        .status()
        .map_err(|error| vec![format!("failed to {description}: {error}")])?;
    if status.success() {
        Ok(())
    } else {
        Err(vec![format!("failed to {description}: {status}")])
    }
}

fn run_output(command: &mut Command, description: &str) -> Result<Output, Vec<String>> {
    let output = command
        .output()
        .map_err(|error| vec![format!("failed to {description}: {error}")])?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(vec![format!("failed to {description}: {}", output.status)])
    }
}

fn command_succeeded(command: &mut Command) -> bool {
    command.status().is_ok_and(|status| status.success())
}

impl Engine {
    fn binary(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }

    fn build_runtime_oci(
        self,
        dockerfile: &Path,
        context: &Path,
        oci_tar: &Path,
        forwarded: &[String],
    ) -> Result<(), Vec<String>> {
        let mut command =
            zainod_runtime_build_command(self, dockerfile, context, oci_tar, forwarded);
        run_command(
            &mut command,
            &format!("run {} container build", self.binary()),
        )?;
        match self {
            Self::Docker => Ok(()),
            Self::Podman => {
                let mut save = Command::new("podman");
                save.args(["save", "--format", "oci-archive", "--output"])
                    .arg(oci_tar)
                    .arg(IMAGE_REF);
                run_command(&mut save, "save podman OCI archive")
            }
        }
    }

    fn build_export(
        self,
        dockerfile: &Path,
        context: &Path,
        forwarded: &[String],
    ) -> Result<(), Vec<String>> {
        let mut command = zainod_export_build_command(self, dockerfile, context, forwarded);
        run_command(
            &mut command,
            &format!("run {} container build", self.binary()),
        )
    }

    fn build_oram_export(
        self,
        dockerfile: &Path,
        context: &Path,
        output_directory: &Path,
    ) -> Result<(), Vec<String>> {
        let mut command = oram_container_build_command(self, dockerfile, context, output_directory);
        run_command(
            &mut command,
            &format!("run {} ORAM container build", self.binary()),
        )
    }
}

fn zainod_runtime_build_command(
    engine: Engine,
    dockerfile: &Path,
    context: &Path,
    oci_tar: &Path,
    forwarded: &[String],
) -> Command {
    match engine {
        Engine::Docker => {
            let output = format!(
                "type=oci,rewrite-timestamp=true,force-compression=true,dest={},name=zainod",
                oci_tar.display()
            );
            container_build_command(
                engine,
                dockerfile,
                context,
                &["--target", "runtime", "--output", &output],
                forwarded,
            )
        }
        Engine::Podman => container_build_command(
            engine,
            dockerfile,
            context,
            &[
                "--target",
                "runtime",
                "--source-date-epoch",
                "1",
                "--rewrite-timestamp",
                "--tag",
                IMAGE_REF,
            ],
            forwarded,
        ),
    }
}

fn zainod_export_build_command(
    engine: Engine,
    dockerfile: &Path,
    context: &Path,
    forwarded: &[String],
) -> Command {
    let local_dest = format!("type=local,dest={}/build", context.display());
    container_build_command(
        engine,
        dockerfile,
        context,
        &["--quiet", "--target", "export", "--output", &local_dest],
        forwarded,
    )
}

fn oram_container_build_command(
    engine: Engine,
    dockerfile: &Path,
    context: &Path,
    output_directory: &Path,
) -> Command {
    let local_dest = format!("type=local,dest={}", output_directory.display());
    let mut flags = Vec::with_capacity(7);
    if engine == Engine::Podman {
        // Rootless Podman otherwise retains full intermediate build layers.
        // This is scoped to the ORAM product; the default zainod flow is unchanged.
        flags.push("--layers=false");
    }
    flags.extend([
        "--no-cache",
        "--quiet",
        "--target",
        "oram-export",
        "--output",
        &local_dest,
    ]);
    container_build_command(engine, dockerfile, context, &flags, &[])
}

fn container_build_command(
    engine: Engine,
    dockerfile: &Path,
    context: &Path,
    per_build: &[&str],
    forwarded: &[String],
) -> Command {
    let mut command = Command::new(engine.binary());
    command
        .arg("build")
        .arg("-f")
        .arg(dockerfile)
        .arg(context)
        .arg("--platform")
        .arg(PLATFORM)
        .args(per_build)
        .args(forwarded)
        .env("SOURCE_DATE_EPOCH", "1");
    match engine {
        Engine::Docker => {
            command.env("DOCKER_BUILDKIT", "1");
        }
        Engine::Podman => {
            command.arg("--format").arg("docker");
        }
    }
    command
}

fn select_engine() -> Result<Engine, Vec<String>> {
    if let Ok(name) = env::var("CONTAINER_ENGINE") {
        return match name.trim() {
            "docker" => Ok(Engine::Docker),
            "podman" => Ok(Engine::Podman),
            other => Err(vec![format!(
                "unsupported CONTAINER_ENGINE={other:?}; expected `docker` or `podman`"
            )]),
        };
    }
    if on_path("podman") {
        Ok(Engine::Podman)
    } else if on_path("docker") {
        Ok(Engine::Docker)
    } else {
        Err(vec![
            "no container engine found: install podman or docker, or set CONTAINER_ENGINE"
                .to_owned(),
        ])
    }
}

fn on_path(binary: &str) -> bool {
    env::var_os("PATH")
        .map(|paths| env::split_paths(&paths).any(|directory| directory.join(binary).is_file()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::ffi::OsStr;
    use std::io::Cursor;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn command_arguments(command: &Command) -> Vec<String> {
        command
            .get_args()
            .map(OsStr::to_string_lossy)
            .map(|argument| argument.into_owned())
            .collect()
    }

    #[test]
    fn arguments_default_to_the_unchanged_zainod_forwarding_path() {
        let request = parse_args(["--build-arg".to_owned(), "NO_TLS=true".to_owned()]);
        assert_eq!(
            request,
            Ok(BuildRequest {
                product: Product::Zainod,
                forwarded: vec!["--build-arg".to_owned(), "NO_TLS=true".to_owned()],
            })
        );
        let explicit = parse_args([
            "--product=zainod".to_owned(),
            "--progress".to_owned(),
            "plain".to_owned(),
        ]);
        assert_eq!(
            explicit,
            Ok(BuildRequest {
                product: Product::Zainod,
                forwarded: vec!["--progress".to_owned(), "plain".to_owned()],
            })
        );
    }

    #[test]
    fn oram_product_forbids_forwarded_unknown_and_duplicate_arguments() {
        assert_eq!(
            parse_args(["--product".to_owned(), ORAM_PRODUCT.to_owned()]),
            Ok(BuildRequest {
                product: Product::ZainodOram,
                forwarded: Vec::new(),
            })
        );
        assert!(parse_args([
            "--product".to_owned(),
            ORAM_PRODUCT.to_owned(),
            "--build-arg".to_owned(),
            "X=1".to_owned(),
        ])
        .is_err());
        assert!(parse_args(["--product=unknown".to_owned()]).is_err());
        assert!(parse_args(["--product".to_owned()]).is_err());
        assert!(
            parse_args(["--product=zainod".to_owned(), "--product=zainod".to_owned(),]).is_err()
        );
    }

    #[test]
    fn porcelain_status_parsing_distinguishes_clean_and_dirty_trees() {
        assert!(parse_status_entries(b"").is_empty());
        assert_eq!(
            parse_status_entries(b" M Dockerfile.deterministic\0?? new file\0"),
            vec![" M Dockerfile.deterministic", "?? new file"]
        );
    }

    #[test]
    fn full_head_parser_requires_full_lowercase_hex() {
        let sha = "12abcdef".repeat(5);
        assert_eq!(parse_full_head(&sha).as_deref(), Ok(sha.as_str()));
        assert!(parse_full_head("12abcdef").is_err());
        assert!(parse_full_head(&"12abcdef".repeat(8)).is_err());
        assert!(parse_full_head(&"AB".repeat(20)).is_err());
    }

    #[test]
    fn streaming_equality_covers_equal_length_and_content_differences() -> TestResult {
        let long = vec![0x5a; 64 * 1024 + 17];
        assert!(readers_equal(
            BufReader::with_capacity(7, Cursor::new(long.clone())),
            BufReader::with_capacity(19, Cursor::new(long.clone())),
        )?);
        let mut changed = long.clone();
        changed[64 * 1024] = 0x33;
        assert!(!readers_equal(
            BufReader::new(Cursor::new(long.clone())),
            BufReader::new(Cursor::new(changed)),
        )?);
        assert!(!readers_equal(
            BufReader::new(Cursor::new(long)),
            BufReader::new(Cursor::new(vec![0x5a; 10])),
        )?);
        Ok(())
    }

    #[test]
    fn atomic_publication_rejects_an_existing_output() -> TestResult {
        let root = create_unique_directory(&env::temp_dir(), "zaino-oram-publish-test")?;
        let stage = root.join("stage");
        let destination = root.join("oram-release");
        fs::create_dir(&stage)?;
        fs::write(stage.join(ORAM_PRODUCT), b"binary")?;
        fs::create_dir(&destination)?;

        assert!(atomic_publish_directory(&stage, &destination).is_err());
        assert!(stage.join(ORAM_PRODUCT).is_file());
        assert!(destination.is_dir());
        remove_directory_if_present(&root)?;
        Ok(())
    }

    #[test]
    fn atomic_publication_moves_the_complete_stage_as_one_directory() -> TestResult {
        let root = create_unique_directory(&env::temp_dir(), "zaino-oram-publish-test")?;
        let stage = root.join("stage");
        let destination = root.join("oram-release");
        fs::create_dir(&stage)?;
        fs::write(stage.join(ORAM_PRODUCT), b"binary")?;
        fs::write(stage.join(ORAM_RECEIPT), b"receipt")?;

        let outcome =
            atomic_publish_directory(&stage, &destination).map_err(|errors| errors.join("; "))?;
        assert_eq!(outcome, AtomicPublishOutcome::PublishedAndSynced);
        assert!(!stage.exists());
        assert_eq!(fs::read(destination.join(ORAM_PRODUCT))?, b"binary");
        assert_eq!(fs::read(destination.join(ORAM_RECEIPT))?, b"receipt");
        remove_directory_if_present(&root)?;
        Ok(())
    }

    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    #[test]
    fn atomic_publication_reports_visible_output_when_parent_sync_fails() -> TestResult {
        let root = create_unique_directory(&env::temp_dir(), "zaino-oram-publish-test")?;
        let stage = root.join("stage");
        let destination = root.join("oram-release");
        fs::create_dir(&stage)?;
        fs::write(stage.join(ORAM_PRODUCT), b"binary")?;

        let outcome = atomic_publish_directory_with_parent_sync(
            &stage,
            &destination,
            |_already_open_parent| {
                assert!(destination.is_dir());
                Err(rustix::io::Errno::IO)
            },
        )
        .map_err(|errors| errors.join("; "))?;
        assert!(matches!(
            outcome,
            AtomicPublishOutcome::PublishedButDurabilityUncertain(_)
        ));
        assert!(!stage.exists());
        assert!(destination.join(ORAM_PRODUCT).is_file());
        remove_directory_if_present(&root)?;
        Ok(())
    }

    #[test]
    fn publication_result_keeps_durability_and_verification_distinct() {
        let destination = Path::new("/build/oram-release");
        let durability = finish_publication(
            destination,
            AtomicPublishOutcome::PublishedButDurabilityUncertain("fsync failed".to_owned()),
            Ok(()),
        );
        let durability_message = match durability {
            Err(errors) => errors.join("; "),
            Ok(()) => panic!("durability failure must remain an error after verification"),
        };
        assert!(durability_message.contains("crash durability is uncertain"));
        assert!(durability_message.contains("self-verification succeeded"));

        let verification = finish_publication(
            destination,
            AtomicPublishOutcome::PublishedAndSynced,
            Err(vec!["verification failed".to_owned()]),
        );
        let verification_message = match verification {
            Err(errors) => errors.join("; "),
            Ok(()) => panic!("verification failure must remain an error after durable publish"),
        };
        assert!(verification_message.contains("supplemental final self-verification failed"));
        assert!(!verification_message.contains("durability is uncertain"));
    }

    #[test]
    fn oram_container_command_is_no_cache_and_has_no_forwarded_args() {
        let command = oram_container_build_command(
            Engine::Docker,
            Path::new("/context/Dockerfile.deterministic"),
            Path::new("/context"),
            Path::new("/out"),
        );
        assert_eq!(command.get_program(), OsStr::new("docker"));
        assert_eq!(
            command_arguments(&command),
            vec![
                "build",
                "-f",
                "/context/Dockerfile.deterministic",
                "/context",
                "--platform",
                "linux/amd64",
                "--no-cache",
                "--quiet",
                "--target",
                "oram-export",
                "--output",
                "type=local,dest=/out",
            ]
        );

        let podman = oram_container_build_command(
            Engine::Podman,
            Path::new("/context/Dockerfile.deterministic"),
            Path::new("/context"),
            Path::new("/out"),
        );
        assert_eq!(
            command_arguments(&podman),
            vec![
                "build",
                "-f",
                "/context/Dockerfile.deterministic",
                "/context",
                "--platform",
                "linux/amd64",
                "--layers=false",
                "--no-cache",
                "--quiet",
                "--target",
                "oram-export",
                "--output",
                "type=local,dest=/out",
                "--format",
                "docker",
            ]
        );
    }

    #[test]
    fn legacy_zainod_container_commands_keep_the_historical_shape() {
        let dockerfile = Path::new("/context/Dockerfile.deterministic");
        let context = Path::new("/context");
        let oci_tar = Path::new("/tmp/zainod-deterministic.oci.tar");
        let forwarded = vec![
            "--build-arg".to_owned(),
            "RUSTFLAGS=-Ctarget-cpu=x86-64".to_owned(),
        ];

        let runtime =
            zainod_runtime_build_command(Engine::Docker, dockerfile, context, oci_tar, &forwarded);
        assert_eq!(
            command_arguments(&runtime),
            vec![
                "build",
                "-f",
                "/context/Dockerfile.deterministic",
                "/context",
                "--platform",
                "linux/amd64",
                "--target",
                "runtime",
                "--output",
                "type=oci,rewrite-timestamp=true,force-compression=true,dest=/tmp/zainod-deterministic.oci.tar,name=zainod",
                "--build-arg",
                "RUSTFLAGS=-Ctarget-cpu=x86-64",
            ]
        );

        let export = zainod_export_build_command(Engine::Docker, dockerfile, context, &forwarded);
        assert_eq!(
            command_arguments(&export),
            vec![
                "build",
                "-f",
                "/context/Dockerfile.deterministic",
                "/context",
                "--platform",
                "linux/amd64",
                "--quiet",
                "--target",
                "export",
                "--output",
                "type=local,dest=/context/build",
                "--build-arg",
                "RUSTFLAGS=-Ctarget-cpu=x86-64",
            ]
        );

        let podman_runtime =
            zainod_runtime_build_command(Engine::Podman, dockerfile, context, oci_tar, &forwarded);
        assert_eq!(
            command_arguments(&podman_runtime),
            vec![
                "build",
                "-f",
                "/context/Dockerfile.deterministic",
                "/context",
                "--platform",
                "linux/amd64",
                "--target",
                "runtime",
                "--source-date-epoch",
                "1",
                "--rewrite-timestamp",
                "--tag",
                "localhost/zainod:deterministic",
                "--build-arg",
                "RUSTFLAGS=-Ctarget-cpu=x86-64",
                "--format",
                "docker",
            ]
        );
    }

    #[test]
    fn receipt_commands_bind_both_binaries_and_verify_with_binary_b() {
        let binary_a = Path::new("/tmp/a/zainod-oram");
        let binary_b = Path::new("/tmp/b/zainod-oram");
        let receipt = Path::new("/tmp/release-receipt.json");
        let revision = "11".repeat(20);
        let create = create_receipt_command(ReceiptInputs {
            binary_a,
            revision: &revision,
            source_archive: Path::new("/tmp/source.tar"),
            cargo_lock: Path::new("/tmp/context/Cargo.lock"),
            rust_toolchain: Path::new("/tmp/context/rust-toolchain.toml"),
            dockerfile: Path::new("/tmp/context/Dockerfile.deterministic"),
            binary_b,
            output: receipt,
        });
        assert_eq!(create.get_program(), binary_a.as_os_str());
        let create_args = command_arguments(&create);
        assert!(create_args
            .windows(2)
            .any(|pair| { pair == ["--reproducible-binary", "/tmp/b/zainod-oram"] }));

        let verify = verify_receipt_command(binary_b, receipt);
        assert_eq!(verify.get_program(), binary_b.as_os_str());
        assert_eq!(
            command_arguments(&verify),
            vec![
                "release",
                "verify-receipt",
                "--receipt",
                "/tmp/release-receipt.json",
            ]
        );
    }

    #[test]
    fn detached_worktree_and_archive_commands_bind_the_exact_revision() {
        let revision = "11".repeat(20);
        let add =
            git_worktree_add_command(Path::new("/repo"), Path::new("/tmp/worktree"), &revision);
        assert_eq!(
            command_arguments(&add),
            vec![
                "-C",
                "/repo",
                "worktree",
                "add",
                "--detach",
                "/tmp/worktree",
                revision.as_str(),
            ]
        );
        let remove = git_worktree_remove_command(Path::new("/repo"), Path::new("/tmp/worktree"));
        assert_eq!(
            command_arguments(&remove),
            vec![
                "-C",
                "/repo",
                "worktree",
                "remove",
                "--force",
                "/tmp/worktree",
            ]
        );
        let archive = git_archive_command(
            Path::new("/tmp/worktree"),
            Path::new("/tmp/source.tar"),
            &revision,
        );
        assert_eq!(
            command_arguments(&archive),
            vec![
                "-C",
                "/tmp/worktree",
                "archive",
                "--format=tar",
                "--output",
                "/tmp/source.tar",
                revision.as_str(),
            ]
        );
    }
}
