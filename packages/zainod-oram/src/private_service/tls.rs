//! The private surface's TLS identity, minted inside the workload.
//!
//! TLS is not decoration on this listener. The envelope keys the
//! `BootstrapSession` route releases are runtime-wide -- every wallet holds
//! the same `request_key`/`response_key` -- so the envelope gives
//! authenticity, epoch binding, and a fixed traffic shape, but *no*
//! client-to-client confidentiality. TLS is the only thing that stops one
//! wallet reading another's traffic, and the only thing that stops a network
//! observer reading both. See `docs/notes/private-query-client-key-establishment.md`.
//!
//! The identity is generated here, in-process, at startup (ADR 0007): the
//! private key is drawn inside the attested workload, is never written to
//! disk, and never leaves this type. An operator-supplied PEM pair would put
//! that key in the operator's hands, which is the custody question ADR 0010
//! exists to avoid.
//!
//! A fresh identity is minted on every start, bound to the key epoch. That is
//! the same rule the symmetric keys already follow -- restart is rotation. A
//! persistent certificate would be the one durable secret in a design that has
//! none, and would have to be stored somewhere the operator can read.
//!
//! What that costs, stated plainly: pinning this certificate is
//! trust-on-first-use *per process*. A wallet that pins a fingerprint learns
//! only that it is still talking to the same process it first talked to. It
//! learns nothing about what binary that process is running, and after a
//! restart the fingerprint changes and the wallet must re-pin -- which is
//! indistinguishable, to the wallet, from being handed a different server.
//! Attestation is what closes that gap; ADR 0010 defers it, and until it
//! lands this is exactly as strong as trusting the operator's deployment.

use std::{
    fmt,
    path::{Path, PathBuf},
};

use base64::Engine as _;
use rcgen::{
    string::Ia5String, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, SanType,
};
use sha2::{Digest, Sha256};
use tonic::transport::{Identity, ServerTlsConfig};

/// The name a wallet presents when connecting, and the certificate's primary
/// subject alternative name.
///
/// A `.invalid` name (RFC 6761) on purpose: this identity is pinned or
/// attested, never resolved. Giving it a resolvable name would invite a
/// wallet to trust DNS for something DNS cannot establish here.
pub(crate) const PRIVATE_SURFACE_DNS_NAME: &str = "private-query.zaino.invalid";

/// Basename of the fingerprint file written into the deployment directory.
pub(crate) const FINGERPRINT_FILE_NAME: &str = "private-tls-fingerprint.txt";

/// PEM bodies wrap at 64 base64 characters (RFC 7468).
const PEM_LINE_WIDTH: usize = 64;

/// The subject alternative name carrying this generation's key epoch.
///
/// The epoch lives in a SAN rather than in the subject because a SAN is the
/// field TLS stacks actually parse and expose: a wallet can read this off the
/// presented certificate through its own TLS library, with no X.509 subject
/// parsing. Modern name verification (RFC 6125) ignores the subject common
/// name entirely, so an epoch placed there would be invisible to exactly the
/// code that needs it. A second SAN also composes: it sits beside
/// [`PRIVATE_SURFACE_DNS_NAME`], so encoding the epoch cannot break the name
/// the wallet actually verifies against.
fn key_epoch_san_name(key_epoch: u64) -> String {
    format!("key-epoch-{key_epoch}.{PRIVATE_SURFACE_DNS_NAME}")
}

/// One process's TLS identity for the private surface.
///
/// The private key half exists only inside this value: there is no accessor
/// for it, and `Debug` does not print it.
pub(crate) struct PrivateTlsIdentity {
    certificate_pem: String,
    private_key_pem: String,
    fingerprint: String,
    key_epoch: u64,
}

impl PrivateTlsIdentity {
    /// Mints this process's identity, bound to `key_epoch`.
    pub(crate) fn generate(key_epoch: u64) -> Result<Self, PrivateTlsError> {
        let signing_key = KeyPair::generate().map_err(|_| PrivateTlsError::Generate)?;

        let mut params = CertificateParams::default();
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, PRIVATE_SURFACE_DNS_NAME);
        params.distinguished_name = distinguished_name;
        params.subject_alt_names = vec![
            SanType::DnsName(dns_name(PRIVATE_SURFACE_DNS_NAME)?),
            SanType::DnsName(dns_name(&key_epoch_san_name(key_epoch))?),
        ];
        // A workload identity signs nothing but itself. `ExplicitNoCa` states
        // that in the certificate rather than leaving it to a default, so a
        // pinning wallet that does check basic constraints sees the intent.
        params.is_ca = IsCa::ExplicitNoCa;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let certificate = params
            .self_signed(&signing_key)
            .map_err(|_| PrivateTlsError::Generate)?;
        let certificate_der = certificate.der();

        Ok(Self {
            fingerprint: hex::encode(Sha256::digest(certificate_der.as_ref())),
            certificate_pem: pem_block("CERTIFICATE", certificate_der.as_ref()),
            private_key_pem: pem_block("PRIVATE KEY", &signing_key.serialize_der()),
            key_epoch,
        })
    }

    /// SHA-256 over the served certificate's DER, lowercase hex.
    ///
    /// This is the value an operator publishes and a wallet pins. Production
    /// reaches it through [`Self::fingerprint_record`], which is the one
    /// rendering stdout and the published file share; this accessor exists so
    /// a test can check that rendering against the certificate actually
    /// served, and is `cfg(test)` so it cannot become a second path to it.
    #[cfg(test)]
    pub(crate) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The public half, PEM encoded.
    ///
    /// Safe to publish -- it is exactly what any handshake presents -- but
    /// nothing in production hands it out: a wallet obtains it from the
    /// handshake and checks it against the published fingerprint. `cfg(test)`
    /// so it stays that way; this is the wallet's side of the pinning path in
    /// the listener tests.
    #[cfg(test)]
    pub(crate) fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }

    /// The acceptor configuration the private listener terminates on.
    pub(crate) fn server_tls_config(&self) -> ServerTlsConfig {
        ServerTlsConfig::new().identity(Identity::from_pem(
            &self.certificate_pem,
            &self.private_key_pem,
        ))
    }

    /// Publishes the fingerprint into `deployment_dir` and reports the path.
    ///
    /// Only the fingerprint: the certificate's private half is never written
    /// anywhere, and the public half is reconstructible from any handshake.
    pub(crate) fn publish_fingerprint(
        &self,
        deployment_dir: &Path,
    ) -> Result<PathBuf, PrivateTlsError> {
        std::fs::create_dir_all(deployment_dir).map_err(|_| PrivateTlsError::PublishFingerprint)?;
        let path = deployment_dir.join(FINGERPRINT_FILE_NAME);
        std::fs::write(&path, self.fingerprint_record())
            .map_err(|_| PrivateTlsError::PublishFingerprint)?;
        Ok(path)
    }

    /// The one line published to stdout and to the fingerprint file.
    ///
    /// Shared by both so an operator comparing the two can never be reading
    /// two differently-formatted renderings of the same fact.
    pub(crate) fn fingerprint_record(&self) -> String {
        format!(
            "private_tls_sha256={fingerprint},key_epoch:{key_epoch},dns_name:{PRIVATE_SURFACE_DNS_NAME}\n",
            fingerprint = self.fingerprint,
            key_epoch = self.key_epoch,
        )
    }
}

impl fmt::Debug for PrivateTlsIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The fingerprint is public by construction; the key is not, and is
        // deliberately absent rather than truncated.
        f.debug_struct("PrivateTlsIdentity")
            .field("fingerprint", &self.fingerprint)
            .field("key_epoch", &self.key_epoch)
            .finish_non_exhaustive()
    }
}

/// Validates one certificate name at the X.509 boundary.
fn dns_name(name: &str) -> Result<Ia5String, PrivateTlsError> {
    Ia5String::try_from(name).map_err(|_| PrivateTlsError::Generate)
}

/// Wraps DER bytes in a PEM block.
///
/// One function for both the certificate and the key: the only difference is
/// the label. Written here rather than through rcgen's `pem` feature, which
/// would add a third crate to do base64 line wrapping the workspace already
/// has an encoder for.
fn pem_block(label: &str, der: &[u8]) -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut block =
        String::with_capacity(body.len() + body.len() / PEM_LINE_WIDTH + 2 * label.len() + 32);
    block.push_str("-----BEGIN ");
    block.push_str(label);
    block.push_str("-----\n");
    let mut start = 0;
    while start < body.len() {
        let end = (start + PEM_LINE_WIDTH).min(body.len());
        // Base64 output is ASCII, so every index here is a char boundary.
        block.push_str(&body[start..end]);
        block.push('\n');
        start = end;
    }
    block.push_str("-----END ");
    block.push_str(label);
    block.push_str("-----\n");
    block
}

/// Uniform failure minting or publishing the private surface's identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrivateTlsError {
    /// No identity could be minted for this process.
    Generate,
    /// The fingerprint could not be published to the deployment directory.
    PublishFingerprint,
}

impl fmt::Display for PrivateTlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Generate => f.write_str("private surface TLS identity could not be generated"),
            Self::PublishFingerprint => {
                f.write_str("private surface TLS fingerprint could not be published")
            }
        }
    }
}

impl std::error::Error for PrivateTlsError {}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_KEY_EPOCH: u64 = 7;

    #[test]
    fn a_generated_identity_reports_a_fingerprint_over_the_certificate_it_serves(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let identity = PrivateTlsIdentity::generate(FIXTURE_KEY_EPOCH)?;
        let der = decode_single_pem_block(identity.certificate_pem(), "CERTIFICATE")?;

        assert_eq!(identity.fingerprint(), hex::encode(Sha256::digest(&der)));
        assert_eq!(identity.fingerprint().len(), 64);
        Ok(())
    }

    #[test]
    fn the_private_key_never_appears_in_a_debug_rendering() -> Result<(), Box<dyn std::error::Error>>
    {
        let identity = PrivateTlsIdentity::generate(FIXTURE_KEY_EPOCH)?;
        let rendered = format!("{identity:?}");

        assert!(rendered.contains(identity.fingerprint()));
        assert!(!rendered.contains("PRIVATE KEY"));
        assert!(!rendered.contains(&identity.private_key_pem));
        Ok(())
    }

    #[test]
    fn two_starts_mint_different_identities() -> Result<(), Box<dyn std::error::Error>> {
        let first = PrivateTlsIdentity::generate(FIXTURE_KEY_EPOCH)?;
        let second = PrivateTlsIdentity::generate(FIXTURE_KEY_EPOCH)?;

        // Same epoch on purpose: the difference must come from a fresh key
        // draw, not from the epoch in the name.
        assert_ne!(first.fingerprint(), second.fingerprint());
        assert_ne!(first.certificate_pem(), second.certificate_pem());
        Ok(())
    }

    #[test]
    fn the_key_epoch_is_carried_in_a_subject_alternative_name(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let identity = PrivateTlsIdentity::generate(FIXTURE_KEY_EPOCH)?;
        let der = decode_single_pem_block(identity.certificate_pem(), "CERTIFICATE")?;
        let expected = key_epoch_san_name(FIXTURE_KEY_EPOCH);

        // The SAN extension stores names as raw IA5 bytes, so the encoded
        // name appears verbatim in the DER. Checked without an X.509 parser
        // on purpose: pulling one in would add a crate to assert one string.
        assert!(contains_subslice(&der, expected.as_bytes()));
        assert!(contains_subslice(&der, PRIVATE_SURFACE_DNS_NAME.as_bytes()));
        Ok(())
    }

    #[test]
    fn publishing_writes_the_same_record_stdout_reports() -> Result<(), Box<dyn std::error::Error>>
    {
        let deployment = tempfile::TempDir::new()?;
        let identity = PrivateTlsIdentity::generate(FIXTURE_KEY_EPOCH)?;
        // A directory the runner has not created yet: publishing must not
        // depend on the journal having been opened first.
        let target = deployment.path().join("not-created-yet");

        let path = identity.publish_fingerprint(&target)?;

        assert_eq!(path, target.join(FINGERPRINT_FILE_NAME));
        let published = std::fs::read_to_string(&path)?;
        assert_eq!(published, identity.fingerprint_record());
        assert!(published.contains(identity.fingerprint()));
        assert!(published.contains("key_epoch:7"));
        assert!(!published.contains("PRIVATE KEY"));
        Ok(())
    }

    #[test]
    fn pem_blocks_wrap_at_the_line_width_and_round_trip() -> Result<(), Box<dyn std::error::Error>>
    {
        let der: Vec<u8> = (0u16..300).map(|byte| byte as u8).collect();
        let block = pem_block("CERTIFICATE", &der);

        assert!(block.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(block.ends_with("-----END CERTIFICATE-----\n"));
        for line in block.lines().skip(1).take_while(|l| !l.starts_with("---")) {
            assert!(line.len() <= PEM_LINE_WIDTH);
        }
        assert_eq!(decode_single_pem_block(&block, "CERTIFICATE")?, der);
        Ok(())
    }

    /// Test-local PEM reader, so these tests decode with something other than
    /// the encoder they are checking.
    fn decode_single_pem_block(
        pem: &str,
        label: &str,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let body: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        if !pem.contains(&format!("-----BEGIN {label}-----")) {
            return Err(format!("no {label} block").into());
        }
        Ok(base64::engine::general_purpose::STANDARD.decode(body)?)
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }
}
