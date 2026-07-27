//! Crate-private Linux process-memory sampling for qualification runners.

use std::{fmt, fs};

/// One whole-process resident-memory and lifetime high-water sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProcessMemorySample {
    rss_bytes: u64,
    hwm_bytes: u64,
}

impl ProcessMemorySample {
    #[cfg(test)]
    pub(super) const fn new(rss_bytes: u64, hwm_bytes: u64) -> Self {
        Self {
            rss_bytes,
            hwm_bytes,
        }
    }

    pub(super) const fn rss_bytes(self) -> u64 {
        self.rss_bytes
    }

    pub(super) const fn hwm_bytes(self) -> u64 {
        self.hwm_bytes
    }
}

/// Process-memory sampling or `/proc` format failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProcessMemoryError;

impl fmt::Display for ProcessMemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("whole-process memory sampling failed")
    }
}

impl std::error::Error for ProcessMemoryError {}

pub(super) fn sample_process_memory() -> Result<ProcessMemorySample, ProcessMemoryError> {
    let status = fs::read_to_string("/proc/self/status").map_err(|_| ProcessMemoryError)?;
    parse_process_status(&status)
}

fn parse_process_status(status: &str) -> Result<ProcessMemorySample, ProcessMemoryError> {
    Ok(ProcessMemorySample {
        rss_bytes: parse_status_kib(status, "VmRSS:")?,
        hwm_bytes: parse_status_kib(status, "VmHWM:")?,
    })
}

fn parse_status_kib(status: &str, field: &str) -> Result<u64, ProcessMemoryError> {
    let Some(value) = status.lines().find_map(|line| line.strip_prefix(field)) else {
        return Err(ProcessMemoryError);
    };
    let mut parts = value.split_ascii_whitespace();
    let Some(number) = parts.next() else {
        return Err(ProcessMemoryError);
    };
    let Some(unit) = parts.next() else {
        return Err(ProcessMemoryError);
    };
    if unit != "kB" || parts.next().is_some() {
        return Err(ProcessMemoryError);
    }
    number
        .parse::<u64>()
        .map_err(|_| ProcessMemoryError)?
        .checked_mul(1_024)
        .ok_or(ProcessMemoryError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_status_memory_fields_and_rejects_partial_or_wrong_units() {
        let sample = parse_process_status("VmHWM:\t4096 kB\nVmRSS:\t3072 kB\n")
            .expect("complete fixed-format status sample must parse");
        assert_eq!(sample.rss_bytes(), 3_145_728);
        assert_eq!(sample.hwm_bytes(), 4_194_304);
        assert!(parse_process_status("VmRSS:\t3072 kB\n").is_err());
        assert!(parse_process_status("VmHWM:\t4096 bytes\nVmRSS:\t3072 kB\n").is_err());
    }
}
