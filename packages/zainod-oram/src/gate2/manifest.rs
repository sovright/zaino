//! Immutable, receipt-bound Gate 2 timing experiment manifests.

use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
};

use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};
use zaino_oram::{
    validate_rostl_timing_shape, EquivalenceBounds, ExperimentPlan, PlanError, RostlTimingError,
    RostlTimingMode, RostlTimingRecordKind, TimingBoundError, TimingSeed, MINIMUM_PAIRS,
};

use crate::{
    corpus_artifact::{
        artifact_blake2s256_hex, open_artifact_directory, publish_verified_artifact,
        read_artifact_file, validate_artifact_file_set, ArtifactDirectory, ArtifactError,
        ArtifactFile,
    },
    execution_identity::{
        release_receipt_metadata_from_canonical_bytes, verify_release_receipt_binding,
        ReleaseReceiptError, ReleaseReceiptMetadata,
    },
    timing_contract::{
        occupancy_window, validate_evidence_intent, EvidenceIntent, TimingContractError,
        DIRECTORY_RECORD_MODEL, LABEL_ASSIGNMENT, ORDER_BLOCKING, STATE_CONTROL, STATISTICAL_SCOPE,
        SUPPORTED_MODES, TARGET_PROJECTION_MODEL, TIMING_EVIDENCE_SCHEMA,
    },
};

const REQUEST_SCHEMA: &str = "zaino-oram-timing-manifest-request-v1";
const MANIFEST_SCHEMA: &str = "zaino-oram-timing-manifest-v1";
const HOST_SCHEMA: &str = "zaino-oram-qualification-host-v1";
const HOST_NORMALIZATION: &str = "boot-scoped-linux-host-inputs-v1";
const EVIDENCE_CONTRACT: &str = "matched-long-lived-timing-v3";
const SEED_DERIVATION: &str = "blake2s256-domain-separated-cell-tuple-u64-v1";
const CELL_SEED_DOMAIN: &[u8] = b"zaino-oram-gate2-cell-seed-v1";
const CODEGEN_PROFILE: &str = "insert-outcome-both-records-both-binaries-v1";
const PHYSICAL_TRACE_PROFILE: &str = "schedule-bound-directory-and-event-v1";
const MANIFEST_JSON: &str = "manifest.json";
const RELEASE_RECEIPT_JSON: &str = "release-receipt.json";
const REQUIRED_FILES: [&str; 2] = [MANIFEST_JSON, RELEASE_RECEIPT_JSON];
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
const MAX_RECEIPT_BYTES: usize = 64 * 1024;
const MAX_HOST_INPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_AXIS_ENTRIES: usize = 64;
const MAX_IDENTIFIER_BYTES: usize = 64;
const DIGEST_HEX_BYTES: usize = 64;

const KERNEL_RELEASE_PATH: &str = "/proc/sys/kernel/osrelease";
const CPU_INFO_PATH: &str = "/proc/cpuinfo";
const MEMORY_INFO_PATH: &str = "/proc/meminfo";
const MACHINE_ID_PATH: &str = "/etc/machine-id";
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
const DMI_VENDOR_PATH: &str = "/sys/class/dmi/id/sys_vendor";
const DMI_PRODUCT_PATH: &str = "/sys/class/dmi/id/product_name";
const DMI_VERSION_PATH: &str = "/sys/class/dmi/id/product_version";

pub(crate) struct TimingManifestCreateInputs {
    pub(crate) request: PathBuf,
    pub(crate) release_receipt: PathBuf,
    pub(crate) output_dir: PathBuf,
}

pub(crate) struct TimingManifestVerifyInputs {
    pub(crate) manifest_dir: PathBuf,
    pub(crate) release_receipt: PathBuf,
    pub(crate) expected_manifest_blake2s256: String,
}

pub(crate) struct TimingManifestInspectInputs {
    pub(crate) manifest_dir: PathBuf,
    pub(crate) expected_manifest_blake2s256: String,
}

pub(crate) struct TimingManifestSummary {
    manifest_blake2s256: String,
    cell_count: usize,
}

impl TimingManifestSummary {
    pub(crate) fn manifest_blake2s256(&self) -> &str {
        &self.manifest_blake2s256
    }

    pub(crate) const fn cell_count(&self) -> usize {
        self.cell_count
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TimingManifestRequestV1 {
    schema: String,
    policy: TimingPolicyV1,
    modes: Vec<RostlTimingMode>,
    occupancy_points: Vec<OccupancyPointV1>,
    repeat_blocks: Vec<RepeatBlockV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TimingPolicyV1 {
    pairs: usize,
    warmup_pairs: usize,
    mean_bound_nanos: f64,
    cdf_distance_bound: f64,
    max_load_average_1m: f64,
    max_competing_processes: usize,
    max_runqueue_wait_ratio: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OccupancyPointV1 {
    id: String,
    directory_capacity: usize,
    directory_initial_occupancy: usize,
    event_capacity: usize,
    event_initial_occupancy: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepeatBlockV1 {
    id: String,
    root_seed_hex: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TimingManifestV1 {
    schema: String,
    runner_version: String,
    request_blake2s256: String,
    release_binding: ReleaseBindingV1,
    host_binding: QualificationHostV1,
    evidence_contract: EvidenceContractV1,
    policy: TimingPolicyV1,
    modes: Vec<RostlTimingMode>,
    occupancy_points: Vec<OccupancyPointV1>,
    repeat_blocks: Vec<RepeatBlockV1>,
    cells: Vec<TimingCellV1>,
    companion_requirements: CompanionRequirementsV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseBindingV1 {
    receipt_blake2s256: String,
    source_revision: String,
    binary_sha256: String,
    binary_size_bytes: u64,
}

impl ReleaseBindingV1 {
    fn from_receipt(receipt: &ReleaseReceiptMetadata) -> Self {
        Self {
            receipt_blake2s256: receipt.receipt_blake2s256().to_owned(),
            source_revision: receipt.source_revision().to_owned(),
            binary_sha256: receipt.binary_sha256().to_owned(),
            binary_size_bytes: receipt.binary_size_bytes(),
        }
    }

    fn validate(&self) -> Result<(), TimingManifestError> {
        validate_lower_hex(&self.receipt_blake2s256, DIGEST_HEX_BYTES)?;
        validate_lower_hex(&self.source_revision, 40)?;
        validate_lower_hex(&self.binary_sha256, DIGEST_HEX_BYTES)?;
        if self.binary_size_bytes == 0 {
            return Err(TimingManifestError::InvalidManifest {
                reason: "release-bound binary size must be nonzero",
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QualificationHostV1 {
    schema: String,
    normalization: String,
    fingerprint_blake2s256: String,
    target_os: String,
    target_arch: String,
    kernel_release: String,
    logical_cpu_count: usize,
    memory_total_kib: u64,
    boot_scoped: bool,
    attested: bool,
    tdx_qualified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct HostFingerprintMaterialV1 {
    normalization: &'static str,
    machine_id: String,
    boot_id: String,
    kernel_release: String,
    cpu: CpuIdentityV1,
    memory_total_kib: u64,
    platform: PlatformIdentityV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CpuIdentityV1 {
    vendor_id: String,
    family: String,
    model: String,
    model_name: String,
    stepping: String,
    microcode: String,
    logical_cpu_count: usize,
    hypervisor_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PlatformIdentityV1 {
    system_vendor: String,
    product_name: String,
    product_version: String,
}

impl QualificationHostV1 {
    fn capture() -> Result<Self, TimingManifestError> {
        if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            return Err(TimingManifestError::UnsupportedHost);
        }
        let material = HostFingerprintMaterialV1 {
            normalization: HOST_NORMALIZATION,
            machine_id: normalized_host_value(
                &read_host_text(MACHINE_ID_PATH, 256)?,
                "machine id",
            )?,
            boot_id: normalized_host_value(&read_host_text(BOOT_ID_PATH, 256)?, "boot id")?,
            kernel_release: normalized_host_value(
                &read_host_text(KERNEL_RELEASE_PATH, 1024)?,
                "kernel release",
            )?,
            cpu: parse_cpu_info(&read_host_text(CPU_INFO_PATH, MAX_HOST_INPUT_BYTES)?)?,
            memory_total_kib: parse_memory_total(&read_host_text(
                MEMORY_INFO_PATH,
                MAX_HOST_INPUT_BYTES,
            )?)?,
            platform: PlatformIdentityV1 {
                system_vendor: normalized_host_value(
                    &read_host_text(DMI_VENDOR_PATH, 4096)?,
                    "DMI system vendor",
                )?,
                product_name: normalized_host_value(
                    &read_host_text(DMI_PRODUCT_PATH, 4096)?,
                    "DMI product name",
                )?,
                product_version: normalized_host_value(
                    &read_host_text(DMI_VERSION_PATH, 4096)?,
                    "DMI product version",
                )?,
            },
        };
        Self::from_material(material)
    }

    fn from_material(material: HostFingerprintMaterialV1) -> Result<Self, TimingManifestError> {
        if material.memory_total_kib == 0 || material.cpu.logical_cpu_count == 0 {
            return Err(TimingManifestError::InvalidHost {
                reason: "host CPU and memory counts must be nonzero",
            });
        }
        let fingerprint_blake2s256 = canonical_digest(&material)?;
        let host = Self {
            schema: HOST_SCHEMA.to_owned(),
            normalization: HOST_NORMALIZATION.to_owned(),
            fingerprint_blake2s256,
            target_os: "linux".to_owned(),
            target_arch: "x86_64".to_owned(),
            kernel_release: material.kernel_release,
            logical_cpu_count: material.cpu.logical_cpu_count,
            memory_total_kib: material.memory_total_kib,
            boot_scoped: true,
            attested: false,
            tdx_qualified: false,
        };
        host.validate()?;
        Ok(host)
    }

    fn validate(&self) -> Result<(), TimingManifestError> {
        if self.schema != HOST_SCHEMA
            || self.normalization != HOST_NORMALIZATION
            || self.target_os != "linux"
            || self.target_arch != "x86_64"
            || self.kernel_release.is_empty()
            || self.logical_cpu_count == 0
            || self.memory_total_kib == 0
            || !self.boot_scoped
            || self.attested
            || self.tdx_qualified
        {
            return Err(TimingManifestError::InvalidManifest {
                reason: "qualification host binding is invalid",
            });
        }
        validate_lower_hex(&self.fingerprint_blake2s256, DIGEST_HEX_BYTES)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceContractV1 {
    name: String,
    raw_timing_schema: String,
    evidence_intent: EvidenceIntent,
    minimum_qualification_pairs: usize,
    state_control: String,
    label_assignment: String,
    order_blocking: String,
    directory_record_model: String,
    event_record_model: String,
    statistical_scope: String,
    target_projection_model: String,
    target_projection_model_implemented: bool,
    independent_process_per_cell_required: bool,
    wall_clock_only: bool,
    physical_trace_complete: bool,
    oram_state_seed_bound: bool,
    serial_independence_established: bool,
    can_clear_gate2: bool,
    seed_derivation: String,
}

impl EvidenceContractV1 {
    fn fixed() -> Self {
        Self {
            name: EVIDENCE_CONTRACT.to_owned(),
            raw_timing_schema: TIMING_EVIDENCE_SCHEMA.to_owned(),
            evidence_intent: EvidenceIntent::QualificationCandidate,
            minimum_qualification_pairs: MINIMUM_PAIRS,
            state_control: STATE_CONTROL.to_owned(),
            label_assignment: LABEL_ASSIGNMENT.to_owned(),
            order_blocking: ORDER_BLOCKING.to_owned(),
            directory_record_model: DIRECTORY_RECORD_MODEL.to_owned(),
            event_record_model: crate::timing_contract::EVENT_RECORD_MODEL.to_owned(),
            statistical_scope: STATISTICAL_SCOPE.to_owned(),
            target_projection_model: TARGET_PROJECTION_MODEL.to_owned(),
            target_projection_model_implemented: false,
            independent_process_per_cell_required: true,
            wall_clock_only: true,
            physical_trace_complete: false,
            oram_state_seed_bound: false,
            serial_independence_established: false,
            can_clear_gate2: false,
            seed_derivation: SEED_DERIVATION.to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TimingCellV1 {
    id: String,
    mode: RostlTimingMode,
    occupancy_point_id: String,
    repeat_block_id: String,
    cell_seed_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CompanionRoleV1 {
    MainBinaryCodegenOutcome,
    TimingBinaryCodegenOutcome,
    DirectoryPhysicalTrace,
    EventPhysicalTrace,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompanionRequirementsV1 {
    codegen_profile: String,
    physical_trace_profile: String,
    roles: Vec<CompanionRoleV1>,
}

impl CompanionRequirementsV1 {
    fn fixed() -> Self {
        Self {
            codegen_profile: CODEGEN_PROFILE.to_owned(),
            physical_trace_profile: PHYSICAL_TRACE_PROFILE.to_owned(),
            roles: vec![
                CompanionRoleV1::MainBinaryCodegenOutcome,
                CompanionRoleV1::TimingBinaryCodegenOutcome,
                CompanionRoleV1::DirectoryPhysicalTrace,
                CompanionRoleV1::EventPhysicalTrace,
            ],
        }
    }
}

impl TimingPolicyV1 {
    fn plan(&self) -> Result<ExperimentPlan, TimingManifestError> {
        validate_evidence_intent(
            EvidenceIntent::QualificationCandidate,
            self.pairs,
            self.warmup_pairs,
        )?;
        let plan = ExperimentPlan::new(self.pairs, self.warmup_pairs, TimingSeed::new(0))?;
        let _ = EquivalenceBounds::new(self.mean_bound_nanos, self.cdf_distance_bound)?;
        if !self.max_load_average_1m.is_finite() || self.max_load_average_1m < 0.0 {
            return Err(TimingManifestError::InvalidRequest {
                reason: "maximum load average must be finite and non-negative",
            });
        }
        if !self.max_runqueue_wait_ratio.is_finite()
            || !(0.0..=1.0).contains(&self.max_runqueue_wait_ratio)
        {
            return Err(TimingManifestError::InvalidRequest {
                reason: "maximum runqueue wait ratio must be finite and within [0, 1]",
            });
        }
        Ok(plan)
    }
}

impl TimingManifestRequestV1 {
    fn load(path: &Path) -> Result<Self, TimingManifestError> {
        let bytes = read_bounded_path(path, MAX_REQUEST_BYTES, "read timing manifest request")?;
        let request: Self = serde_json::from_slice(&bytes)?;
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), TimingManifestError> {
        if self.schema != REQUEST_SCHEMA {
            return Err(TimingManifestError::InvalidRequest {
                reason: "timing manifest request schema mismatch",
            });
        }
        if self.modes != SUPPORTED_MODES {
            return Err(TimingManifestError::InvalidRequest {
                reason: "timing manifest must declare all supported modes in canonical order",
            });
        }
        if self.occupancy_points.is_empty()
            || self.occupancy_points.len() > MAX_AXIS_ENTRIES
            || self.repeat_blocks.is_empty()
            || self.repeat_blocks.len() > MAX_AXIS_ENTRIES
        {
            return Err(TimingManifestError::InvalidRequest {
                reason: "timing manifest axes must be nonempty and within the structural limit",
            });
        }
        let plan = self.policy.plan()?;

        validate_sorted_identifiers(
            self.occupancy_points.iter().map(|point| point.id.as_str()),
            "occupancy point identifiers must be unique and sorted",
        )?;
        let mut point_shapes = BTreeSet::new();
        for point in &self.occupancy_points {
            let shape = (
                point.directory_capacity,
                point.directory_initial_occupancy,
                point.event_capacity,
                point.event_initial_occupancy,
            );
            if !point_shapes.insert(shape) {
                return Err(TimingManifestError::InvalidRequest {
                    reason: "occupancy point shapes must be unique",
                });
            }
            validate_rostl_timing_shape(
                RostlTimingRecordKind::Directory,
                point.directory_capacity,
                point.directory_initial_occupancy,
                &plan,
            )?;
            validate_rostl_timing_shape(
                RostlTimingRecordKind::Event,
                point.event_capacity,
                point.event_initial_occupancy,
                &plan,
            )?;
            let _ = occupancy_window(point.directory_initial_occupancy, &plan)?;
            let _ = occupancy_window(point.event_initial_occupancy, &plan)?;
        }

        validate_sorted_identifiers(
            self.repeat_blocks.iter().map(|block| block.id.as_str()),
            "repeat block identifiers must be unique and sorted",
        )?;
        let mut seeds = BTreeSet::new();
        for block in &self.repeat_blocks {
            let seed = parse_seed(&block.root_seed_hex)?;
            if !seeds.insert(seed) {
                return Err(TimingManifestError::InvalidRequest {
                    reason: "repeat block root seeds must be unique",
                });
            }
        }
        self.cell_count()?;
        Ok(())
    }

    fn cell_count(&self) -> Result<usize, TimingManifestError> {
        self.repeat_blocks
            .len()
            .checked_mul(self.occupancy_points.len())
            .and_then(|count| count.checked_mul(self.modes.len()))
            .ok_or(TimingManifestError::InvalidRequest {
                reason: "timing manifest cell count overflows usize",
            })
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, TimingManifestError> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }
}

impl TimingManifestV1 {
    fn new(
        request: TimingManifestRequestV1,
        release: ReleaseBindingV1,
        host: QualificationHostV1,
        runner_version: &str,
    ) -> Result<Self, TimingManifestError> {
        request.validate()?;
        if runner_version.is_empty() {
            return Err(TimingManifestError::InvalidManifest {
                reason: "timing manifest runner version is empty",
            });
        }
        let request_blake2s256 = artifact_blake2s256_hex(&request.canonical_bytes()?);
        let cells = materialize_cells(&request)?;
        let manifest = Self {
            schema: MANIFEST_SCHEMA.to_owned(),
            runner_version: runner_version.to_owned(),
            request_blake2s256,
            release_binding: release,
            host_binding: host,
            evidence_contract: EvidenceContractV1::fixed(),
            policy: request.policy,
            modes: request.modes,
            occupancy_points: request.occupancy_points,
            repeat_blocks: request.repeat_blocks,
            cells,
            companion_requirements: CompanionRequirementsV1::fixed(),
        };
        manifest.validate()?;
        Ok(manifest)
    }

    fn request(&self) -> TimingManifestRequestV1 {
        TimingManifestRequestV1 {
            schema: REQUEST_SCHEMA.to_owned(),
            policy: self.policy.clone(),
            modes: self.modes.clone(),
            occupancy_points: self.occupancy_points.clone(),
            repeat_blocks: self.repeat_blocks.clone(),
        }
    }

    fn validate(&self) -> Result<(), TimingManifestError> {
        if self.schema != MANIFEST_SCHEMA || self.runner_version.is_empty() {
            return Err(TimingManifestError::InvalidManifest {
                reason: "timing manifest identity is invalid",
            });
        }
        self.release_binding.validate()?;
        self.host_binding.validate()?;
        if self.evidence_contract != EvidenceContractV1::fixed()
            || self.companion_requirements != CompanionRequirementsV1::fixed()
        {
            return Err(TimingManifestError::InvalidManifest {
                reason: "timing manifest fixed evidence contract is invalid",
            });
        }
        let request = self.request();
        let expected_request_digest = artifact_blake2s256_hex(&request.canonical_bytes()?);
        if self.request_blake2s256 != expected_request_digest {
            return Err(TimingManifestError::InvalidManifest {
                reason: "timing manifest request digest mismatch",
            });
        }
        if self.cells != materialize_cells(&request)? {
            return Err(TimingManifestError::InvalidManifest {
                reason: "timing manifest cells are not the canonical Cartesian product",
            });
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, TimingManifestError> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }

    fn digest(&self) -> Result<String, TimingManifestError> {
        Ok(artifact_blake2s256_hex(&self.canonical_bytes()?))
    }
}

struct LoadedTimingManifest {
    manifest: TimingManifestV1,
    release_receipt_bytes: Vec<u8>,
}

impl LoadedTimingManifest {
    fn summary(&self) -> Result<TimingManifestSummary, TimingManifestError> {
        Ok(TimingManifestSummary {
            manifest_blake2s256: self.manifest.digest()?,
            cell_count: self.manifest.cells.len(),
        })
    }
}

pub(crate) fn create_timing_manifest(
    inputs: TimingManifestCreateInputs,
    runner_version: &str,
) -> Result<TimingManifestSummary, TimingManifestError> {
    let request = TimingManifestRequestV1::load(&inputs.request)?;
    let verified_receipt = verify_release_receipt_binding(&inputs.release_receipt)?;
    let host = QualificationHostV1::capture()?;
    let manifest = TimingManifestV1::new(
        request,
        ReleaseBindingV1::from_receipt(verified_receipt.metadata()),
        host,
        runner_version,
    )?;
    publish_manifest_artifact(
        &inputs.output_dir,
        &manifest,
        verified_receipt.canonical_bytes(),
    )?;
    let loaded = load_manifest_artifact(&inputs.output_dir)?;
    if loaded.manifest != manifest
        || loaded.release_receipt_bytes != verified_receipt.canonical_bytes()
    {
        return Err(TimingManifestError::PublishedReadbackMismatch);
    }
    loaded.summary()
}

pub(crate) fn verify_timing_manifest(
    inputs: TimingManifestVerifyInputs,
    runner_version: &str,
) -> Result<TimingManifestSummary, TimingManifestError> {
    let loaded = load_manifest_artifact(&inputs.manifest_dir)?;
    let summary = validate_expected_manifest_digest(&loaded, &inputs.expected_manifest_blake2s256)?;
    if loaded.manifest.runner_version != runner_version {
        return Err(TimingManifestError::RunnerVersionMismatch);
    }
    let verified_receipt = verify_release_receipt_binding(&inputs.release_receipt)?;
    if loaded.release_receipt_bytes != verified_receipt.canonical_bytes()
        || loaded.manifest.release_binding
            != ReleaseBindingV1::from_receipt(verified_receipt.metadata())
    {
        return Err(TimingManifestError::ReleaseBindingMismatch);
    }
    let current_host = QualificationHostV1::capture()?;
    if loaded.manifest.host_binding != current_host {
        return Err(TimingManifestError::HostBindingMismatch);
    }
    Ok(summary)
}

pub(crate) fn inspect_timing_manifest(
    inputs: TimingManifestInspectInputs,
) -> Result<TimingManifestSummary, TimingManifestError> {
    let loaded = load_manifest_artifact(&inputs.manifest_dir)?;
    validate_expected_manifest_digest(&loaded, &inputs.expected_manifest_blake2s256)
}

fn validate_expected_manifest_digest(
    loaded: &LoadedTimingManifest,
    expected_manifest_blake2s256: &str,
) -> Result<TimingManifestSummary, TimingManifestError> {
    validate_lower_hex(expected_manifest_blake2s256, DIGEST_HEX_BYTES)?;
    let summary = loaded.summary()?;
    if summary.manifest_blake2s256 != expected_manifest_blake2s256 {
        return Err(TimingManifestError::ManifestDigestMismatch);
    }
    Ok(summary)
}

fn publish_manifest_artifact(
    output_dir: &Path,
    manifest: &TimingManifestV1,
    release_receipt_bytes: &[u8],
) -> Result<(), TimingManifestError> {
    let manifest_bytes = manifest.canonical_bytes()?;
    let files = [
        ArtifactFile::new(MANIFEST_JSON, manifest_bytes),
        ArtifactFile::new(RELEASE_RECEIPT_JSON, release_receipt_bytes.to_vec()),
    ];
    publish_verified_artifact(output_dir, &files, |stage| {
        validate_staged_manifest(stage, manifest, release_receipt_bytes).map_err(|_| {
            ArtifactError::InvalidArtifact {
                reason: "staged timing manifest failed semantic read-back validation",
            }
        })
    })?;
    Ok(())
}

fn validate_staged_manifest(
    stage: &ArtifactDirectory,
    expected_manifest: &TimingManifestV1,
    expected_receipt: &[u8],
) -> Result<(), TimingManifestError> {
    validate_artifact_file_set(stage, &REQUIRED_FILES)?;
    let manifest_bytes = read_artifact_file(stage, MANIFEST_JSON, MAX_MANIFEST_BYTES)?;
    let receipt_bytes = read_artifact_file(stage, RELEASE_RECEIPT_JSON, MAX_RECEIPT_BYTES)?;
    let manifest: TimingManifestV1 = serde_json::from_slice(&manifest_bytes)?;
    manifest.validate()?;
    validate_release_binding(&manifest, &receipt_bytes)?;
    if manifest.canonical_bytes()? != manifest_bytes
        || manifest != *expected_manifest
        || receipt_bytes != expected_receipt
    {
        return Err(TimingManifestError::StagedReadbackMismatch);
    }
    Ok(())
}

fn load_manifest_artifact(
    manifest_dir: &Path,
) -> Result<LoadedTimingManifest, TimingManifestError> {
    let directory = open_artifact_directory(manifest_dir)?;
    validate_artifact_file_set(&directory, &REQUIRED_FILES)?;
    let manifest_bytes = read_artifact_file(&directory, MANIFEST_JSON, MAX_MANIFEST_BYTES)?;
    let release_receipt_bytes =
        read_artifact_file(&directory, RELEASE_RECEIPT_JSON, MAX_RECEIPT_BYTES)?;
    let manifest: TimingManifestV1 = serde_json::from_slice(&manifest_bytes)?;
    manifest.validate()?;
    if manifest.canonical_bytes()? != manifest_bytes {
        return Err(TimingManifestError::NonCanonicalManifest);
    }
    validate_release_binding(&manifest, &release_receipt_bytes)?;
    Ok(LoadedTimingManifest {
        manifest,
        release_receipt_bytes,
    })
}

fn validate_release_binding(
    manifest: &TimingManifestV1,
    release_receipt_bytes: &[u8],
) -> Result<(), TimingManifestError> {
    let receipt_metadata = release_receipt_metadata_from_canonical_bytes(release_receipt_bytes)?;
    if artifact_blake2s256_hex(release_receipt_bytes) != manifest.release_binding.receipt_blake2s256
        || manifest.release_binding != ReleaseBindingV1::from_receipt(&receipt_metadata)
    {
        return Err(TimingManifestError::ReleaseBindingMismatch);
    }
    Ok(())
}

fn materialize_cells(
    request: &TimingManifestRequestV1,
) -> Result<Vec<TimingCellV1>, TimingManifestError> {
    let mut cells = Vec::with_capacity(request.cell_count()?);
    let mut cell_seeds = BTreeSet::new();
    for block in &request.repeat_blocks {
        let repeat_root = parse_seed(&block.root_seed_hex)?;
        for point in &request.occupancy_points {
            for mode in request.modes.iter().copied() {
                let cell_seed = derive_cell_seed(repeat_root, &point.id, mode);
                if !cell_seeds.insert(cell_seed) {
                    return Err(TimingManifestError::InvalidRequest {
                        reason: "derived timing cell seeds must be unique",
                    });
                }
                cells.push(TimingCellV1 {
                    id: format!("{}::{}::{}", block.id, point.id, mode_name(mode)),
                    mode,
                    occupancy_point_id: point.id.clone(),
                    repeat_block_id: block.id.clone(),
                    cell_seed_hex: format!("{cell_seed:016x}"),
                });
            }
        }
    }
    Ok(cells)
}

fn derive_cell_seed(repeat_root: u64, occupancy_point_id: &str, mode: RostlTimingMode) -> u64 {
    let mut digest = Blake2s256::new();
    digest.update(CELL_SEED_DOMAIN);
    digest.update(repeat_root.to_be_bytes());
    digest.update((occupancy_point_id.len() as u64).to_be_bytes());
    digest.update(occupancy_point_id.as_bytes());
    digest.update(mode_name(mode).as_bytes());
    let digest = digest.finalize();
    u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ])
}

const fn mode_name(mode: RostlTimingMode) -> &'static str {
    match mode {
        RostlTimingMode::HitMiss => "hit_miss",
        RostlTimingMode::ForcedHit => "forced_hit",
        RostlTimingMode::ForcedMiss => "forced_miss",
    }
}

fn parse_seed(seed: &str) -> Result<u64, TimingManifestError> {
    if seed.len() != 16
        || !seed
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(TimingManifestError::InvalidRequest {
            reason: "repeat root seed must be exactly 16 lowercase hex characters",
        });
    }
    u64::from_str_radix(seed, 16).map_err(|_| TimingManifestError::InvalidRequest {
        reason: "repeat root seed is not valid hexadecimal",
    })
}

fn validate_identifier(identifier: &str) -> Result<(), TimingManifestError> {
    let bytes = identifier.as_bytes();
    let valid = !bytes.is_empty()
        && bytes.len() <= MAX_IDENTIFIER_BYTES
        && bytes[0].is_ascii_lowercase()
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(*byte, b'-' | b'_')
        });
    if valid {
        Ok(())
    } else {
        Err(TimingManifestError::InvalidRequest {
            reason: "axis identifiers must be lowercase filename-safe names",
        })
    }
}

fn validate_sorted_identifiers<'a>(
    identifiers: impl IntoIterator<Item = &'a str>,
    reason: &'static str,
) -> Result<(), TimingManifestError> {
    let mut previous: Option<&str> = None;
    for identifier in identifiers {
        validate_identifier(identifier)?;
        if previous.is_some_and(|previous| previous >= identifier) {
            return Err(TimingManifestError::InvalidRequest { reason });
        }
        previous = Some(identifier);
    }
    Ok(())
}

fn validate_lower_hex(value: &str, expected_len: usize) -> Result<(), TimingManifestError> {
    if value.len() != expected_len
        || value.bytes().all(|byte| byte == b'0')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Err(TimingManifestError::InvalidManifest {
            reason: "manifest digest field is not canonical nonzero lowercase hex",
        })
    } else {
        Ok(())
    }
}

fn canonical_digest(value: &impl Serialize) -> Result<String, TimingManifestError> {
    Ok(artifact_blake2s256_hex(&serde_json::to_vec(value)?))
}

fn read_bounded_path(
    path: &Path,
    maximum_bytes: usize,
    operation: &'static str,
) -> Result<Vec<u8>, TimingManifestError> {
    let file = File::open(path).map_err(|source| TimingManifestError::Io { operation, source })?;
    let mut bytes = Vec::new();
    file.take(maximum_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| TimingManifestError::Io { operation, source })?;
    if bytes.is_empty() || bytes.len() > maximum_bytes {
        return Err(TimingManifestError::InvalidRequest {
            reason: "timing manifest input is empty or exceeds its byte limit",
        });
    }
    Ok(bytes)
}

fn read_host_text(path: &str, maximum_bytes: usize) -> Result<String, TimingManifestError> {
    let bytes = read_bounded_path(
        Path::new(path),
        maximum_bytes,
        "read qualification host input",
    )?;
    String::from_utf8(bytes).map_err(|_| TimingManifestError::InvalidHost {
        reason: "qualification host input is not UTF-8",
    })
}

fn normalized_host_value(value: &str, label: &'static str) -> Result<String, TimingManifestError> {
    let normalized = value
        .split_whitespace()
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join(" ");
    if normalized.is_empty()
        || matches!(
            normalized.as_str(),
            "unknown" | "none" | "not specified" | "to be filled by o.e.m."
        )
    {
        Err(TimingManifestError::InvalidHost { reason: label })
    } else {
        Ok(normalized)
    }
}

fn parse_cpu_info(input: &str) -> Result<CpuIdentityV1, TimingManifestError> {
    let mut expected: Option<CpuIdentityV1> = None;
    let mut logical_cpu_count = 0usize;
    for stanza in input.split("\n\n") {
        let field = |name: &str| {
            stanza.lines().find_map(|line| {
                let (key, value) = line.split_once(':')?;
                (key.trim() == name).then(|| value.trim())
            })
        };
        if field("processor").is_none() {
            continue;
        }
        logical_cpu_count =
            logical_cpu_count
                .checked_add(1)
                .ok_or(TimingManifestError::InvalidHost {
                    reason: "logical CPU count overflows usize",
                })?;
        let flags = field("flags").ok_or(TimingManifestError::InvalidHost {
            reason: "CPU flags are missing",
        })?;
        let observed = CpuIdentityV1 {
            vendor_id: normalized_host_value(
                field("vendor_id").ok_or(TimingManifestError::InvalidHost {
                    reason: "CPU vendor is missing",
                })?,
                "CPU vendor is invalid",
            )?,
            family: normalized_host_value(
                field("cpu family").ok_or(TimingManifestError::InvalidHost {
                    reason: "CPU family is missing",
                })?,
                "CPU family is invalid",
            )?,
            model: normalized_host_value(
                field("model").ok_or(TimingManifestError::InvalidHost {
                    reason: "CPU model is missing",
                })?,
                "CPU model is invalid",
            )?,
            model_name: normalized_host_value(
                field("model name").ok_or(TimingManifestError::InvalidHost {
                    reason: "CPU model name is missing",
                })?,
                "CPU model name is invalid",
            )?,
            stepping: normalized_host_value(
                field("stepping").ok_or(TimingManifestError::InvalidHost {
                    reason: "CPU stepping is missing",
                })?,
                "CPU stepping is invalid",
            )?,
            microcode: normalized_host_value(
                field("microcode").ok_or(TimingManifestError::InvalidHost {
                    reason: "CPU microcode is missing",
                })?,
                "CPU microcode is invalid",
            )?,
            logical_cpu_count: 0,
            hypervisor_present: flags.split_whitespace().any(|flag| flag == "hypervisor"),
        };
        if let Some(previous) = &expected {
            if previous.vendor_id != observed.vendor_id
                || previous.family != observed.family
                || previous.model != observed.model
                || previous.model_name != observed.model_name
                || previous.stepping != observed.stepping
                || previous.microcode != observed.microcode
                || previous.hypervisor_present != observed.hypervisor_present
            {
                return Err(TimingManifestError::InvalidHost {
                    reason: "heterogeneous CPU identity is unsupported",
                });
            }
        } else {
            expected = Some(observed);
        }
    }
    let mut cpu = expected.ok_or(TimingManifestError::InvalidHost {
        reason: "CPU information contains no processor stanzas",
    })?;
    cpu.logical_cpu_count = logical_cpu_count;
    Ok(cpu)
}

fn parse_memory_total(input: &str) -> Result<u64, TimingManifestError> {
    let line = input
        .lines()
        .find(|line| line.starts_with("MemTotal:"))
        .ok_or(TimingManifestError::InvalidHost {
            reason: "MemTotal is missing",
        })?;
    let mut fields = line.split_whitespace();
    if fields.next() != Some("MemTotal:") {
        return Err(TimingManifestError::InvalidHost {
            reason: "MemTotal label is malformed",
        });
    }
    let total = fields
        .next()
        .ok_or(TimingManifestError::InvalidHost {
            reason: "MemTotal value is missing",
        })?
        .parse::<u64>()
        .map_err(|_| TimingManifestError::InvalidHost {
            reason: "MemTotal value is malformed",
        })?;
    if fields.next() != Some("kB") || fields.next().is_some() || total == 0 {
        return Err(TimingManifestError::InvalidHost {
            reason: "MemTotal unit or value is invalid",
        });
    }
    Ok(total)
}

#[derive(Debug)]
pub(crate) enum TimingManifestError {
    UnsupportedHost,
    InvalidRequest {
        reason: &'static str,
    },
    InvalidManifest {
        reason: &'static str,
    },
    InvalidHost {
        reason: &'static str,
    },
    ReleaseBindingMismatch,
    HostBindingMismatch,
    RunnerVersionMismatch,
    ManifestDigestMismatch,
    NonCanonicalManifest,
    StagedReadbackMismatch,
    PublishedReadbackMismatch,
    Artifact(ArtifactError),
    ReleaseReceipt(ReleaseReceiptError),
    TimingContract(TimingContractError),
    Plan(PlanError),
    Bounds(TimingBoundError),
    Shape(RostlTimingError),
    Json(serde_json::Error),
    Io {
        operation: &'static str,
        source: io::Error,
    },
}

impl fmt::Display for TimingManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedHost => {
                formatter.write_str("timing manifest host binding requires Linux x86_64")
            }
            Self::InvalidRequest { reason }
            | Self::InvalidManifest { reason }
            | Self::InvalidHost { reason } => formatter.write_str(reason),
            Self::ReleaseBindingMismatch => {
                formatter.write_str("timing manifest release receipt binding mismatch")
            }
            Self::HostBindingMismatch => {
                formatter.write_str("timing manifest qualification host binding mismatch")
            }
            Self::RunnerVersionMismatch => {
                formatter.write_str("timing manifest runner version mismatch")
            }
            Self::ManifestDigestMismatch => {
                formatter.write_str("timing manifest digest does not match retained expectation")
            }
            Self::NonCanonicalManifest => {
                formatter.write_str("timing manifest JSON is not canonical")
            }
            Self::StagedReadbackMismatch => {
                formatter.write_str("staged timing manifest differs after read-back")
            }
            Self::PublishedReadbackMismatch => {
                formatter.write_str("published timing manifest differs after read-back")
            }
            Self::Artifact(_) => formatter.write_str("timing manifest artifact operation failed"),
            Self::ReleaseReceipt(_) => {
                formatter.write_str("timing manifest release receipt verification failed")
            }
            Self::TimingContract(error) => error.fmt(formatter),
            Self::Plan(error) => error.fmt(formatter),
            Self::Bounds(error) => error.fmt(formatter),
            Self::Shape(error) => error.fmt(formatter),
            Self::Json(_) => formatter.write_str("timing manifest JSON is invalid"),
            Self::Io { operation, .. } => write!(formatter, "failed to {operation}"),
        }
    }
}

impl Error for TimingManifestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Artifact(error) => Some(error),
            Self::ReleaseReceipt(error) => Some(error),
            Self::TimingContract(error) => Some(error),
            Self::Plan(error) => Some(error),
            Self::Bounds(error) => Some(error),
            Self::Shape(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<ArtifactError> for TimingManifestError {
    fn from(error: ArtifactError) -> Self {
        Self::Artifact(error)
    }
}

impl From<ReleaseReceiptError> for TimingManifestError {
    fn from(error: ReleaseReceiptError) -> Self {
        Self::ReleaseReceipt(error)
    }
}

impl From<TimingContractError> for TimingManifestError {
    fn from(error: TimingContractError) -> Self {
        Self::TimingContract(error)
    }
}

impl From<PlanError> for TimingManifestError {
    fn from(error: PlanError) -> Self {
        Self::Plan(error)
    }
}

impl From<TimingBoundError> for TimingManifestError {
    fn from(error: TimingBoundError) -> Self {
        Self::Bounds(error)
    }
}

impl From<RostlTimingError> for TimingManifestError {
    fn from(error: RostlTimingError) -> Self {
        Self::Shape(error)
    }
}

impl From<serde_json::Error> for TimingManifestError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    use std::os::unix::fs::symlink;
    use std::{collections::BTreeSet, error::Error, ffi::OsString, fs};

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn policy() -> TimingPolicyV1 {
        TimingPolicyV1 {
            pairs: MINIMUM_PAIRS,
            warmup_pairs: 50,
            mean_bound_nanos: 1_000.0,
            cdf_distance_bound: 0.1,
            max_load_average_1m: 1.0,
            max_competing_processes: 0,
            max_runqueue_wait_ratio: 0.01,
        }
    }

    fn request() -> TimingManifestRequestV1 {
        TimingManifestRequestV1 {
            schema: REQUEST_SCHEMA.to_owned(),
            policy: policy(),
            modes: SUPPORTED_MODES.to_vec(),
            occupancy_points: vec![
                OccupancyPointV1 {
                    id: "low".to_owned(),
                    directory_capacity: 1_024,
                    directory_initial_occupancy: 8,
                    event_capacity: 1_024,
                    event_initial_occupancy: 16,
                },
                OccupancyPointV1 {
                    id: "peak".to_owned(),
                    directory_capacity: 2_048,
                    directory_initial_occupancy: 256,
                    event_capacity: 2_048,
                    event_initial_occupancy: 384,
                },
            ],
            repeat_blocks: vec![
                RepeatBlockV1 {
                    id: "repeat-a".to_owned(),
                    root_seed_hex: "0000000000000001".to_owned(),
                },
                RepeatBlockV1 {
                    id: "repeat-b".to_owned(),
                    root_seed_hex: "0000000000000002".to_owned(),
                },
            ],
        }
    }

    fn release() -> TestResult<ReleaseBindingV1> {
        let receipt = crate::execution_identity::canonical_test_release_receipt()?;
        let metadata = release_receipt_metadata_from_canonical_bytes(&receipt)?;
        Ok(ReleaseBindingV1::from_receipt(&metadata))
    }

    fn host_material() -> HostFingerprintMaterialV1 {
        HostFingerprintMaterialV1 {
            normalization: HOST_NORMALIZATION,
            machine_id: "machine".to_owned(),
            boot_id: "boot".to_owned(),
            kernel_release: "6.8.0".to_owned(),
            cpu: CpuIdentityV1 {
                vendor_id: "vendor".to_owned(),
                family: "6".to_owned(),
                model: "85".to_owned(),
                model_name: "model".to_owned(),
                stepping: "7".to_owned(),
                microcode: "0x1".to_owned(),
                logical_cpu_count: 16,
                hypervisor_present: true,
            },
            memory_total_kib: 65_536,
            platform: PlatformIdentityV1 {
                system_vendor: "vendor".to_owned(),
                product_name: "product".to_owned(),
                product_version: "version".to_owned(),
            },
        }
    }

    fn manifest() -> TestResult<TimingManifestV1> {
        Ok(TimingManifestV1::new(
            request(),
            release()?,
            QualificationHostV1::from_material(host_material())?,
            "test-runner",
        )?)
    }

    fn publish_fixture(output: &Path) -> TestResult<(TimingManifestV1, Vec<u8>)> {
        let receipt = crate::execution_identity::canonical_test_release_receipt()?;
        let manifest = manifest()?;
        publish_manifest_artifact(output, &manifest, &receipt)?;
        Ok((manifest, receipt))
    }

    #[test]
    fn manifest_materializes_the_complete_canonical_matrix() -> TestResult {
        let manifest = manifest()?;

        assert_eq!(manifest.cells.len(), 12);
        assert_eq!(manifest.cells[0].id, "repeat-a::low::hit_miss");
        assert_eq!(manifest.cells[1].id, "repeat-a::low::forced_hit");
        assert_eq!(manifest.cells[2].id, "repeat-a::low::forced_miss");
        assert_eq!(manifest.cells[11].id, "repeat-b::peak::forced_miss");
        assert_ne!(
            manifest.cells[0].cell_seed_hex,
            manifest.cells[1].cell_seed_hex
        );
        assert_ne!(
            manifest.cells[0].cell_seed_hex,
            manifest.cells[3].cell_seed_hex
        );
        Ok(())
    }

    #[test]
    fn canonical_manifest_digest_is_stable_and_has_no_embedded_id() -> TestResult {
        let manifest = manifest()?;
        let bytes = manifest.canonical_bytes()?;
        let decoded: TimingManifestV1 = serde_json::from_slice(&bytes)?;

        assert_eq!(decoded, manifest);
        assert_eq!(decoded.digest()?, manifest.digest()?);
        assert_eq!(
            manifest.digest()?,
            "cd41918dcc3bf62fd80cacc6792d7f72f23b798d9d120ba749fa96d804417bad"
        );
        assert!(!String::from_utf8(bytes)?.contains("manifest_id"));
        Ok(())
    }

    #[test]
    fn request_rejects_incomplete_modes_and_duplicate_axes() {
        let mut incomplete = request();
        incomplete.modes.pop();
        assert!(incomplete.validate().is_err());

        let mut duplicate_point = request();
        let mut alias = duplicate_point.occupancy_points[0].clone();
        alias.id = "z-alias".to_owned();
        duplicate_point.occupancy_points.push(alias);
        assert!(duplicate_point.validate().is_err());

        let mut unsorted_points = request();
        unsorted_points.occupancy_points.swap(0, 1);
        assert!(unsorted_points.validate().is_err());

        let mut duplicate_seed = request();
        duplicate_seed.repeat_blocks[1].root_seed_hex =
            duplicate_seed.repeat_blocks[0].root_seed_hex.clone();
        assert!(duplicate_seed.validate().is_err());

        let mut unsorted_blocks = request();
        unsorted_blocks.repeat_blocks.swap(0, 1);
        assert!(unsorted_blocks.validate().is_err());
    }

    #[test]
    fn cell_seed_derivation_is_tuple_bound_and_unique() -> TestResult {
        let mut request = request();
        request.repeat_blocks[0].root_seed_hex = "0000000000000100".to_owned();
        request.repeat_blocks[1].root_seed_hex = "0000000000000101".to_owned();
        let cells = materialize_cells(&request)?;
        let seeds = cells
            .iter()
            .map(|cell| cell.cell_seed_hex.as_str())
            .collect::<BTreeSet<_>>();

        assert_eq!(seeds.len(), cells.len());
        assert_eq!(
            derive_cell_seed(0x100, "low", RostlTimingMode::HitMiss),
            0xcc00_8a44_69d3_2b4b
        );
        Ok(())
    }

    #[test]
    fn request_rejects_invalid_policy_and_growth_shape() {
        let mut invalid_pairs = request();
        invalid_pairs.policy.pairs = MINIMUM_PAIRS - 1;
        assert!(invalid_pairs.validate().is_err());

        let mut invalid_bound = request();
        invalid_bound.policy.cdf_distance_bound = 2.0;
        assert!(invalid_bound.validate().is_err());

        let mut no_headroom = request();
        no_headroom.occupancy_points[0].directory_capacity = 512;
        assert!(no_headroom.validate().is_err());
    }

    #[test]
    fn request_unknown_fields_are_rejected() -> TestResult {
        let mut value = serde_json::to_value(request())?;
        value["extra"] = serde_json::json!(true);

        assert!(serde_json::from_value::<TimingManifestRequestV1>(value).is_err());
        Ok(())
    }

    #[test]
    fn host_parser_rejects_heterogeneous_cpu_identity() {
        let one = "processor: 0\nvendor_id: v\ncpu family: 6\nmodel: 1\nmodel name: m\nstepping: 1\nmicrocode: x\nflags: hypervisor\n";
        let two = "processor: 1\nvendor_id: v\ncpu family: 6\nmodel: 2\nmodel name: m\nstepping: 1\nmicrocode: x\nflags: hypervisor\n";

        assert!(parse_cpu_info(&format!("{one}\n{two}")).is_err());
    }

    #[test]
    fn manifest_publication_is_exact_and_no_clobber() -> TestResult {
        let parent = tempfile::tempdir()?;
        let output = parent.path().join("manifest");
        let (manifest, receipt) = publish_fixture(&output)?;

        let loaded = load_manifest_artifact(&output)?;
        assert_eq!(loaded.manifest, manifest);
        assert_eq!(loaded.release_receipt_bytes, receipt);
        assert!(publish_manifest_artifact(&output, &manifest, &receipt).is_err());

        let names = fs::read_dir(&output)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<BTreeSet<_>, _>>()?;
        assert_eq!(
            names,
            BTreeSet::from([
                OsString::from(MANIFEST_JSON),
                OsString::from(RELEASE_RECEIPT_JSON),
            ])
        );
        Ok(())
    }

    #[test]
    fn retained_inspection_is_offline_and_execution_admission_checks_version() -> TestResult {
        let parent = tempfile::tempdir()?;
        let output = parent.path().join("manifest");
        let (manifest, _) = publish_fixture(&output)?;
        let expected_digest = manifest.digest()?;

        let summary = inspect_timing_manifest(TimingManifestInspectInputs {
            manifest_dir: output.clone(),
            expected_manifest_blake2s256: expected_digest.clone(),
        })?;
        assert_eq!(summary.manifest_blake2s256(), expected_digest);

        assert!(matches!(
            inspect_timing_manifest(TimingManifestInspectInputs {
                manifest_dir: output.clone(),
                expected_manifest_blake2s256: "f".repeat(DIGEST_HEX_BYTES),
            }),
            Err(TimingManifestError::ManifestDigestMismatch)
        ));
        assert!(matches!(
            verify_timing_manifest(
                TimingManifestVerifyInputs {
                    manifest_dir: output.clone(),
                    release_receipt: output.join(RELEASE_RECEIPT_JSON),
                    expected_manifest_blake2s256: expected_digest,
                },
                "wrong-runner-version",
            ),
            Err(TimingManifestError::RunnerVersionMismatch)
        ));
        Ok(())
    }

    #[test]
    fn execution_admission_rejects_a_valid_manifest_substitution() -> TestResult {
        let parent = tempfile::tempdir()?;
        let original_output = parent.path().join("original");
        let (original, _) = publish_fixture(&original_output)?;

        let substituted_output = parent.path().join("substituted");
        let receipt = crate::execution_identity::canonical_test_release_receipt()?;
        let mut substituted_request = request();
        substituted_request.policy.mean_bound_nanos += 1.0;
        let substituted = TimingManifestV1::new(
            substituted_request,
            release()?,
            QualificationHostV1::from_material(host_material())?,
            "test-runner",
        )?;
        publish_manifest_artifact(&substituted_output, &substituted, &receipt)?;

        assert!(matches!(
            verify_timing_manifest(
                TimingManifestVerifyInputs {
                    manifest_dir: substituted_output.clone(),
                    release_receipt: substituted_output.join(RELEASE_RECEIPT_JSON),
                    expected_manifest_blake2s256: original.digest()?,
                },
                "test-runner",
            ),
            Err(TimingManifestError::ManifestDigestMismatch)
        ));
        Ok(())
    }

    #[test]
    fn manifest_loader_rejects_file_set_and_canonical_json_tampering() -> TestResult {
        let parent = tempfile::tempdir()?;

        let extra_output = parent.path().join("extra");
        publish_fixture(&extra_output)?;
        fs::write(extra_output.join("unexpected"), b"unexpected")?;
        assert!(load_manifest_artifact(&extra_output).is_err());

        let missing_output = parent.path().join("missing");
        publish_fixture(&missing_output)?;
        fs::remove_file(missing_output.join(MANIFEST_JSON))?;
        assert!(load_manifest_artifact(&missing_output).is_err());

        let noncanonical_output = parent.path().join("noncanonical");
        publish_fixture(&noncanonical_output)?;
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(noncanonical_output.join(MANIFEST_JSON))?)?;
        fs::write(
            noncanonical_output.join(MANIFEST_JSON),
            serde_json::to_vec_pretty(&value)?,
        )?;
        assert!(matches!(
            load_manifest_artifact(&noncanonical_output),
            Err(TimingManifestError::NonCanonicalManifest)
        ));
        Ok(())
    }

    #[test]
    fn manifest_loader_rejects_semantic_and_receipt_binding_tampering() -> TestResult {
        let parent = tempfile::tempdir()?;

        let cell_output = parent.path().join("cell");
        let (mut cell_manifest, _) = publish_fixture(&cell_output)?;
        cell_manifest.cells[0].cell_seed_hex = "0000000000000001".to_owned();
        fs::write(
            cell_output.join(MANIFEST_JSON),
            serde_json::to_vec(&cell_manifest)?,
        )?;
        assert!(load_manifest_artifact(&cell_output).is_err());

        let contract_output = parent.path().join("contract");
        let (mut contract_manifest, _) = publish_fixture(&contract_output)?;
        contract_manifest.evidence_contract.can_clear_gate2 = true;
        fs::write(
            contract_output.join(MANIFEST_JSON),
            serde_json::to_vec(&contract_manifest)?,
        )?;
        assert!(load_manifest_artifact(&contract_output).is_err());

        let release_output = parent.path().join("release");
        let (mut release_manifest, _) = publish_fixture(&release_output)?;
        release_manifest.release_binding.binary_size_bytes += 1;
        fs::write(
            release_output.join(MANIFEST_JSON),
            serde_json::to_vec(&release_manifest)?,
        )?;
        assert!(matches!(
            load_manifest_artifact(&release_output),
            Err(TimingManifestError::ReleaseBindingMismatch)
        ));
        Ok(())
    }

    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    #[test]
    fn manifest_loader_rejects_symlink_and_oversized_files() -> TestResult {
        let parent = tempfile::tempdir()?;

        let symlink_output = parent.path().join("symlink");
        publish_fixture(&symlink_output)?;
        let receipt_path = symlink_output.join(RELEASE_RECEIPT_JSON);
        let replacement = parent.path().join("replacement-receipt.json");
        fs::write(
            &replacement,
            crate::execution_identity::canonical_test_release_receipt()?,
        )?;
        fs::remove_file(&receipt_path)?;
        symlink(&replacement, &receipt_path)?;
        assert!(load_manifest_artifact(&symlink_output).is_err());

        let root_output = parent.path().join("root-target");
        publish_fixture(&root_output)?;
        let root_alias = parent.path().join("root-alias");
        symlink(&root_output, &root_alias)?;
        assert!(load_manifest_artifact(&root_alias).is_err());

        let oversized_output = parent.path().join("oversized");
        publish_fixture(&oversized_output)?;
        fs::write(
            oversized_output.join(MANIFEST_JSON),
            vec![b' '; MAX_MANIFEST_BYTES + 1],
        )?;
        assert!(load_manifest_artifact(&oversized_output).is_err());
        Ok(())
    }

    #[test]
    fn host_binding_hides_raw_identity_and_changes_with_private_inputs() -> TestResult {
        let mut material = host_material();
        material.machine_id = "private-machine-7eb9".to_owned();
        material.boot_id = "private-boot-a14c".to_owned();
        material.cpu.model_name = "private-cpu-63f2".to_owned();
        material.platform.product_name = "private-platform-9d81".to_owned();
        let host = QualificationHostV1::from_material(material.clone())?;
        let encoded = String::from_utf8(serde_json::to_vec(&host)?)?;

        for private_value in [
            &material.machine_id,
            &material.boot_id,
            &material.cpu.model_name,
            &material.platform.product_name,
        ] {
            assert!(!encoded.contains(private_value));
        }
        assert!(!encoded.contains("cpu_identity_blake2s256"));
        assert!(!encoded.contains("platform_identity_blake2s256"));

        let mut changed_boot = material.clone();
        changed_boot.boot_id.push_str("-changed");
        assert_ne!(
            host.fingerprint_blake2s256,
            QualificationHostV1::from_material(changed_boot)?.fingerprint_blake2s256
        );

        let mut changed_cpu = material;
        changed_cpu.cpu.microcode.push_str("-changed");
        assert_ne!(
            host.fingerprint_blake2s256,
            QualificationHostV1::from_material(changed_cpu)?.fingerprint_blake2s256
        );
        Ok(())
    }
}
