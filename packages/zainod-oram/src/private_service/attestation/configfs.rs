//! Linux ConfigFS TSM raw-quote acquisition.

use std::{fmt, path::PathBuf};

#[cfg(target_os = "linux")]
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(target_os = "linux")]
use super::MAX_RAW_QUOTE_BYTES;
use super::{RawQuoteProvider, REPORT_DATA_BYTES};

const REPORT_ROOT: &str = "/sys/kernel/config/tsm/report";
#[cfg(any(test, target_os = "linux"))]
const EXPECTED_PROVIDER: &str = "tdx_guest";
#[cfg(target_os = "linux")]
const MAX_ATTRIBUTE_BYTES: usize = 64;
#[cfg(target_os = "linux")]
const CREATE_ATTEMPTS: u64 = 32;
#[cfg(target_os = "linux")]
static REPORT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Production raw-quote provider for the Linux ConfigFS TSM ABI.
pub(crate) struct ConfigFsTsmQuoteProvider {
    root: PathBuf,
}

impl ConfigFsTsmQuoteProvider {
    pub(crate) fn new() -> Self {
        Self {
            root: PathBuf::from(REPORT_ROOT),
        }
    }

    #[cfg(all(test, target_os = "linux"))]
    fn at(root: PathBuf) -> Self {
        Self { root }
    }
}

impl fmt::Debug for ConfigFsTsmQuoteProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConfigFsTsmQuoteProvider { provider: tdx_guest, .. }")
    }
}

impl RawQuoteProvider for ConfigFsTsmQuoteProvider {
    type Error = ConfigFsQuoteError;

    fn quote(&mut self, report_data: [u8; REPORT_DATA_BYTES]) -> Result<Vec<u8>, Self::Error> {
        #[cfg(target_os = "linux")]
        {
            let report = ReportDirectory::create(&self.root)?;
            require_provider(&report.path)?;
            let before = read_generation(&report.path)?;
            if before != 0 {
                return Err(ConfigFsQuoteError::GenerationConflict);
            }
            write_inblob(&report.path, &report_data)?;
            let quote = read_bounded(&report.path.join("outblob"), MAX_RAW_QUOTE_BYTES)?;
            if quote.is_empty() {
                return Err(ConfigFsQuoteError::EmptyQuote);
            }
            let after = read_generation(&report.path)?;
            if !generation_advanced_once(before, after) {
                return Err(ConfigFsQuoteError::GenerationConflict);
            }
            report.cleanup()?;
            Ok(quote)
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (&self.root, report_data);
            Err(ConfigFsQuoteError::UnsupportedPlatform)
        }
    }
}

#[cfg(target_os = "linux")]
struct ReportDirectory {
    path: PathBuf,
    cleaned: bool,
}

#[cfg(target_os = "linux")]
impl ReportDirectory {
    fn create(root: &Path) -> Result<Self, ConfigFsQuoteError> {
        for _ in 0..CREATE_ATTEMPTS {
            let sequence = REPORT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = root.join(format!("zaino-{}-{sequence}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    return Ok(Self {
                        path,
                        cleaned: false,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(ConfigFsQuoteError::CreateReport),
            }
        }
        Err(ConfigFsQuoteError::NameExhausted)
    }
}

#[cfg(target_os = "linux")]
impl Drop for ReportDirectory {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = std::fs::remove_dir(&self.path);
        }
    }
}

#[cfg(target_os = "linux")]
impl ReportDirectory {
    fn cleanup(mut self) -> Result<(), ConfigFsQuoteError> {
        std::fs::remove_dir(&self.path).map_err(|_| ConfigFsQuoteError::Cleanup)?;
        self.cleaned = true;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn require_provider(report: &Path) -> Result<(), ConfigFsQuoteError> {
    let provider = read_bounded(&report.join("provider"), MAX_ATTRIBUTE_BYTES)?;
    validate_provider(&provider)
}

#[cfg(any(test, target_os = "linux"))]
fn validate_provider(provider: &[u8]) -> Result<(), ConfigFsQuoteError> {
    if provider.strip_suffix(b"\n").unwrap_or(provider) == EXPECTED_PROVIDER.as_bytes() {
        Ok(())
    } else {
        Err(ConfigFsQuoteError::WrongProvider)
    }
}

#[cfg(target_os = "linux")]
fn read_generation(report: &Path) -> Result<u64, ConfigFsQuoteError> {
    let bytes = read_bounded(&report.join("generation"), MAX_ATTRIBUTE_BYTES)?;
    parse_generation(&bytes)
}

#[cfg(any(test, target_os = "linux"))]
fn parse_generation(bytes: &[u8]) -> Result<u64, ConfigFsQuoteError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ConfigFsQuoteError::InvalidGeneration)?;
    text.trim()
        .parse()
        .map_err(|_| ConfigFsQuoteError::InvalidGeneration)
}

#[cfg(any(test, target_os = "linux"))]
fn generation_advanced_once(before: u64, after: u64) -> bool {
    before.checked_add(1) == Some(after)
}

#[cfg(target_os = "linux")]
fn write_inblob(
    report: &Path,
    report_data: &[u8; REPORT_DATA_BYTES],
) -> Result<(), ConfigFsQuoteError> {
    let mut inblob = OpenOptions::new()
        .write(true)
        .open(report.join("inblob"))
        .map_err(|_| ConfigFsQuoteError::WriteReportData)?;
    inblob
        .write_all(report_data)
        .map_err(|_| ConfigFsQuoteError::WriteReportData)?;
    // ConfigFS commits binary attributes from the file release callback.
    drop(inblob);
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, ConfigFsQuoteError> {
    let file = File::open(path).map_err(|_| ConfigFsQuoteError::ReadAttribute)?;
    let limit = u64::try_from(maximum)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(ConfigFsQuoteError::ReadAttribute)?;
    let mut bytes = Vec::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| ConfigFsQuoteError::ReadAttribute)?;
    if bytes.len() > maximum {
        return Err(ConfigFsQuoteError::AttributeTooLarge);
    }
    Ok(bytes)
}

/// A ConfigFS TSM quote was not acquired.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigFsQuoteError {
    #[cfg(not(target_os = "linux"))]
    UnsupportedPlatform,
    CreateReport,
    NameExhausted,
    ReadAttribute,
    AttributeTooLarge,
    WrongProvider,
    InvalidGeneration,
    WriteReportData,
    EmptyQuote,
    GenerationConflict,
    Cleanup,
}

impl fmt::Display for ConfigFsQuoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TDX ConfigFS raw quote unavailable")
    }
}

impl std::error::Error for ConfigFsQuoteError {}

#[cfg(test)]
mod validation_tests {
    use super::*;

    #[test]
    fn provider_and_generation_validation_fail_closed() {
        assert_eq!(validate_provider(b"tdx_guest\n"), Ok(()));
        assert_eq!(
            validate_provider(b"sev_guest\n"),
            Err(ConfigFsQuoteError::WrongProvider)
        );
        assert_eq!(parse_generation(b"17\n"), Ok(17));
        assert_eq!(
            parse_generation(b"invalid"),
            Err(ConfigFsQuoteError::InvalidGeneration)
        );
        assert!(generation_advanced_once(0, 1));
        assert!(!generation_advanced_once(0, 2));
        assert!(!generation_advanced_once(u64::MAX, 0));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn bounded_reads_accept_the_limit_and_reject_one_more() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::TempDir::new()?;
        let path = directory.path().join("attribute");
        std::fs::write(&path, vec![7; MAX_RAW_QUOTE_BYTES])?;
        assert_eq!(
            read_bounded(&path, MAX_RAW_QUOTE_BYTES)?.len(),
            MAX_RAW_QUOTE_BYTES
        );
        std::fs::write(&path, vec![7; MAX_RAW_QUOTE_BYTES + 1])?;
        assert_eq!(
            read_bounded(&path, MAX_RAW_QUOTE_BYTES),
            Err(ConfigFsQuoteError::AttributeTooLarge)
        );
        Ok(())
    }

    #[test]
    fn report_directory_is_unique_and_cleaned_up() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::TempDir::new()?;
        let first = ReportDirectory::create(root.path())?;
        let first_path = first.path.clone();
        let second = ReportDirectory::create(root.path())?;
        assert_ne!(first.path, second.path);
        drop(first);
        assert!(!first_path.exists());
        drop(second);
        assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
        Ok(())
    }

    #[test]
    fn absent_configfs_fails_closed() {
        let root = tempfile::TempDir::new().expect("temporary directory is available");
        let mut provider = ConfigFsTsmQuoteProvider::at(root.path().join("absent"));
        assert_eq!(
            provider.quote([0; REPORT_DATA_BYTES]),
            Err(ConfigFsQuoteError::CreateReport)
        );
    }

    #[test]
    fn report_data_write_is_exact_and_missing_attribute_is_refused(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let report = tempfile::TempDir::new()?;
        let inblob = report.path().join("inblob");
        std::fs::write(&inblob, [])?;
        let report_data = [0x5a; REPORT_DATA_BYTES];

        write_inblob(report.path(), &report_data)?;
        assert_eq!(std::fs::read(inblob)?, report_data);

        std::fs::remove_file(report.path().join("inblob"))?;
        assert_eq!(
            write_inblob(report.path(), &report_data),
            Err(ConfigFsQuoteError::WriteReportData)
        );
        Ok(())
    }

    #[test]
    fn missing_and_wrong_provider_attributes_fail_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let report = tempfile::TempDir::new()?;
        assert_eq!(
            require_provider(report.path()),
            Err(ConfigFsQuoteError::ReadAttribute)
        );
        std::fs::write(report.path().join("provider"), b"sev_guest\n")?;
        assert_eq!(
            require_provider(report.path()),
            Err(ConfigFsQuoteError::WrongProvider)
        );
        Ok(())
    }

    #[test]
    fn missing_bounded_read_is_refused() {
        let report = tempfile::TempDir::new().expect("temporary report directory is created");
        assert_eq!(
            read_bounded(&report.path().join("missing"), 1),
            Err(ConfigFsQuoteError::ReadAttribute)
        );
    }

    #[test]
    fn explicit_cleanup_reports_success_and_failure() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::TempDir::new()?;
        let clean = ReportDirectory::create(root.path())?;
        let clean_path = clean.path.clone();
        clean.cleanup()?;
        assert!(!clean_path.exists());

        let nonempty = ReportDirectory::create(root.path())?;
        std::fs::write(nonempty.path.join("attribute"), b"occupied")?;
        assert_eq!(nonempty.cleanup(), Err(ConfigFsQuoteError::Cleanup));
        Ok(())
    }
}
