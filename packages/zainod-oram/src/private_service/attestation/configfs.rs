//! Linux ConfigFS TSM quote provider adapter.

pub(crate) use zaino_tdx_evidence::{ConfigFsQuoteError, ConfigFsTsmQuoteProvider};

use super::{RawQuoteProvider, REPORT_DATA_BYTES};

impl RawQuoteProvider for ConfigFsTsmQuoteProvider {
    type Error = ConfigFsQuoteError;

    fn quote(&mut self, report_data: [u8; REPORT_DATA_BYTES]) -> Result<Vec<u8>, Self::Error> {
        ConfigFsTsmQuoteProvider::quote(self, report_data)
    }
}
