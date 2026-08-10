//! The private surface's TLS identity, minted inside the workload and kept
//! across restarts.
//!
//! TLS is not decoration on this listener. The envelope keys the
//! `BootstrapSession` route releases are runtime-wide -- every wallet holds
//! the same `request_key`/`response_key` -- so the envelope gives
//! authenticity, epoch binding, and a fixed traffic shape, but *no*
//! client-to-client confidentiality. TLS is the only thing that stops one
//! wallet reading another's traffic, and the only thing that stops a network
//! observer reading both. See `docs/notes/private-query-client-key-establishment.md`.
//!
//! The identity is generated here, in-process, on first start (ADR 0007): the
//! private key is drawn inside the workload rather than handed in by an
//! operator.
//!
//! # Why it persists, when the symmetric keys do not
//!
//! The symmetric keys rotate on every restart, and a wallet holding retired
//! ones learns so: the cleartext `key_epoch` earns it a `StaleKeyEpoch` answer
//! and it re-bootstraps. That recovery path runs *above* TLS. A rotating
//! certificate would break a wallet's pin *below* it -- an opaque handshake
//! failure, with no way to reach `BootstrapSession` to discover why, and no
//! way to tell rotation from substitution. Tying certificate lifetime to key
//! lifetime looks consistent and is not: they are separate concerns, and the
//! layer that can explain itself is the one that should be allowed to change.
//!
//! So the certificate and its key are written to the deployment directory on
//! first start and reused on every start after. Rotation is an explicit
//! operator action -- delete the files -- never an implicit consequence of a
//! restart.
//!
//! # What that costs: a private key at rest
//!
//! The private key is now on disk, readable by the operator. That is
//! acceptable *specifically* under ADR 0010's interim posture, where the
//! operator is honest-but-curious and is not the adversary; the adversaries in
//! scope are network observers and other clients, and neither gains anything
//! from a key the operator could always have read out of process memory.
//! The key file is created owner-only (0600) and this module refuses to load
//! one that is not.
//!
//! **This must be revisited as the posture tightens toward ADR 0007.** Against
//! an operator who is in scope, a key at rest is a key the operator holds, and
//! the answer there is a TEE-sealed key or an attested ephemeral one -- not
//! this.
//!
//! # What a pin is worth
//!
//! Better than it was, and worth stating without overclaiming. The fingerprint
//! is stable across restarts, so a wallet pins once and keeps it; a broken pin
//! now means something actually changed rather than "the process bounced". But
//! a pin still only establishes that the wallet is talking to the *same* thing
//! it talked to last time. It says nothing about *what* that thing is -- which
//! binary is running, whether the workload is the measured one. Only
//! attestation answers that, and ADR 0010 defers it; when it lands it
//! supersedes pinning entirely.

use std::{
    fmt,
    fs::File,
    io::Write as _,
    path::{Path, PathBuf},
    time::Duration,
};

use base64::Engine as _;
use rcgen::{
    string::Ia5String, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, SanType,
};
use sha2::{Digest, Sha256};
use tonic::transport::{Identity, ServerTlsConfig};

/// The name a wallet presents when connecting, and the certificate's only
/// subject alternative name.
///
/// A `.invalid` name (RFC 6761) on purpose: this identity is pinned or
/// attested, never resolved. Giving it a resolvable name would invite a
/// wallet to trust DNS for something DNS cannot establish here.
pub(crate) const PRIVATE_SURFACE_DNS_NAME: &str = "private-query.zaino.invalid";

/// Basename of the fingerprint file published into the deployment directory.
pub(crate) const FINGERPRINT_FILE_NAME: &str = "private-tls-fingerprint.txt";
/// Basename of the persisted certificate. Public; safe to read or copy.
const CERTIFICATE_FILE_NAME: &str = "private-tls-cert.pem";
/// Basename of the persisted private key. Owner-only; see the module header.
const PRIVATE_KEY_FILE_NAME: &str = "private-tls-key.pem";

/// PEM bodies wrap at 64 base64 characters (RFC 7468).
const PEM_LINE_WIDTH: usize = 64;

/// Ceiling on how long one TLS handshake may hold a connection permit.
///
/// The listener admits 32 concurrent connections and the permit is taken at
/// accept, before the handshake. Without a bound, a peer that opens a
/// connection and never speaks holds one of the 32 forever. A TLS 1.3
/// handshake is one round trip plus a key exchange -- tens of milliseconds on
/// any usable link, a few hundred on a bad mobile one -- so ten seconds is
/// roughly two orders of magnitude of headroom over a legitimate wallet's
/// worst case while capping a stalled handshake's hold at ten seconds instead
/// of indefinitely. Deliberately generous rather than tight: refusing a slow
/// but honest wallet costs more here than tolerating a slow attacker, who is
/// already bounded to 32 connections.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// One deployment's TLS identity for the private surface.
///
/// The private key half exists in this value and in its owner-only file: there
/// is no accessor for it, and `Debug` does not print it.
pub(crate) struct PrivateTlsIdentity {
    certificate_pem: String,
    private_key_pem: String,
    fingerprint: String,
}

impl PrivateTlsIdentity {
    /// Loads this deployment's identity, minting it on first start.
    ///
    /// Never silently regenerates. A certificate that exists but cannot be
    /// read, parsed, or trusted is an error naming the file: regenerating over
    /// it would break every wallet's pin with no signal, which is the exact
    /// failure the persisted identity exists to prevent. Rotation is deleting
    /// both files, on purpose, by hand.
    pub(crate) fn load_or_generate(deployment_dir: &Path) -> Result<Self, PrivateTlsError> {
        std::fs::create_dir_all(deployment_dir).map_err(|_| PrivateTlsError::Unwritable {
            path: deployment_dir.to_path_buf(),
        })?;
        let certificate_path = deployment_dir.join(CERTIFICATE_FILE_NAME);
        let key_path = deployment_dir.join(PRIVATE_KEY_FILE_NAME);
        match (certificate_path.exists(), key_path.exists()) {
            (true, true) => Self::load(&certificate_path, &key_path),
            (false, false) => Self::generate_into(&certificate_path, &key_path),
            // Half an identity is not a fresh deployment. Minting over it
            // would produce a certificate whose fingerprint nobody published.
            (true, false) => Err(PrivateTlsError::Incomplete {
                present: certificate_path,
                missing: key_path,
            }),
            (false, true) => Err(PrivateTlsError::Incomplete {
                present: key_path,
                missing: certificate_path,
            }),
        }
    }

    /// Reads and validates an identity a previous start persisted.
    fn load(certificate_path: &Path, key_path: &Path) -> Result<Self, PrivateTlsError> {
        require_owner_only(key_path)?;
        let certificate_pem = read_to_string(certificate_path)?;
        let private_key_pem = read_to_string(key_path)?;
        let certificate_der = validated_der(&certificate_pem, "CERTIFICATE", certificate_path)?;
        // The key is validated but its bytes are dropped: nothing outside this
        // value ever needs them, and the check is only that a serving attempt
        // will not fail on a truncated file after the port is already bound.
        validated_der(&private_key_pem, "PRIVATE KEY", key_path)?;
        Ok(Self {
            fingerprint: hex::encode(Sha256::digest(&certificate_der)),
            certificate_pem,
            private_key_pem,
        })
    }

    /// Mints this deployment's identity and persists it.
    fn generate_into(certificate_path: &Path, key_path: &Path) -> Result<Self, PrivateTlsError> {
        let identity = Self::generate()?;
        // The key first, and with `create_new`, so a racing second start
        // fails rather than overwriting an identity the winner is about to
        // publish. The certificate follows, leaving the pair either absent or
        // complete for the next start's `Incomplete` check.
        write_owner_only(key_path, &identity.private_key_pem)?;
        write_public(certificate_path, &identity.certificate_pem)?;
        Ok(identity)
    }

    /// Mints one self-signed identity, touching no disk.
    ///
    /// The certificate names exactly one thing: the surface a wallet verifies
    /// against. Nothing else is encoded into it. The key epoch used to be, and
    /// must not be now -- this certificate outlives many epochs, so a baked-in
    /// one would be wrong from the next restart onward and would actively
    /// mislead a wallet that read it. The same objection retires the other
    /// candidates: the service namespace id tracks the capture, which can be
    /// upgraded under a stable deployment directory, and `profile_label` is
    /// documented in the proto as diagnostic and explicitly not for pinning.
    /// A name that can go stale is worse than no name.
    fn generate() -> Result<Self, PrivateTlsError> {
        let signing_key = KeyPair::generate().map_err(|_| PrivateTlsError::Generate)?;

        let mut params = CertificateParams::default();
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, PRIVATE_SURFACE_DNS_NAME);
        params.distinguished_name = distinguished_name;
        params.subject_alt_names = vec![SanType::DnsName(dns_name(PRIVATE_SURFACE_DNS_NAME)?)];
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
    /// Safe to publish -- it is exactly what any handshake presents, and it
    /// sits in the deployment directory unrestricted -- but nothing in
    /// production hands it out: a wallet obtains it from the handshake and
    /// checks it against the published fingerprint. `cfg(test)` so it stays
    /// that way; this is the wallet's side of the pinning path in the
    /// listener tests.
    #[cfg(test)]
    pub(crate) fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }

    /// The acceptor configuration the private listener terminates on.
    pub(crate) fn server_tls_config(&self) -> ServerTlsConfig {
        ServerTlsConfig::new()
            .identity(Identity::from_pem(
                &self.certificate_pem,
                &self.private_key_pem,
            ))
            .timeout(HANDSHAKE_TIMEOUT)
    }

    /// Publishes the fingerprint into `deployment_dir` and reports the path.
    ///
    /// If a record is already there it is checked, not overwritten: a
    /// disagreement between the published fingerprint and the loaded
    /// certificate means the pair on disk is not the pair operators told
    /// wallets to expect, and serving through it would silently invalidate
    /// every pin. Only the fingerprint is published here; the certificate and
    /// key are written once, by [`Self::load_or_generate`].
    pub(crate) fn publish_fingerprint(
        &self,
        deployment_dir: &Path,
    ) -> Result<PathBuf, PrivateTlsError> {
        std::fs::create_dir_all(deployment_dir).map_err(|_| PrivateTlsError::Unwritable {
            path: deployment_dir.to_path_buf(),
        })?;
        let path = deployment_dir.join(FINGERPRINT_FILE_NAME);
        let record = self.fingerprint_record();
        if path.exists() {
            let published = read_to_string(&path)?;
            if published.trim() != record.trim() {
                return Err(PrivateTlsError::FingerprintMismatch { path });
            }
            return Ok(path);
        }
        write_public(&path, &record)?;
        Ok(path)
    }

    /// The one line published to stdout and to the fingerprint file.
    ///
    /// Shared by both so an operator comparing the two can never be reading
    /// two differently-formatted renderings of the same fact. It carries only
    /// values that outlive a restart, which is why the key epoch is absent.
    pub(crate) fn fingerprint_record(&self) -> String {
        format!(
            "private_tls_sha256={fingerprint},dns_name:{PRIVATE_SURFACE_DNS_NAME}\n",
            fingerprint = self.fingerprint,
        )
    }
}

impl fmt::Debug for PrivateTlsIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The fingerprint is public by construction; the key is not, and is
        // deliberately absent rather than truncated.
        f.debug_struct("PrivateTlsIdentity")
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

/// Validates one certificate name at the X.509 boundary.
fn dns_name(name: &str) -> Result<Ia5String, PrivateTlsError> {
    Ia5String::try_from(name).map_err(|_| PrivateTlsError::Generate)
}

/// Reads a persisted identity file, naming it if it cannot be read.
fn read_to_string(path: &Path) -> Result<String, PrivateTlsError> {
    std::fs::read_to_string(path).map_err(|_| PrivateTlsError::Unreadable {
        path: path.to_path_buf(),
    })
}

/// Decodes one PEM block and checks it is a complete DER structure.
///
/// This is the fail-closed gate: anything it rejects becomes a named error
/// rather than a fresh certificate. It is a structural check, not a full X.509
/// parse -- pulling an ASN.1 parser in to reject what the acceptor would
/// reject anyway is not worth a crate. Whatever slips past here still fails
/// closed, one layer later, when the acceptor is built.
fn validated_der(pem: &str, label: &str, path: &Path) -> Result<Vec<u8>, PrivateTlsError> {
    let malformed = |reason: &'static str| PrivateTlsError::Malformed {
        path: path.to_path_buf(),
        reason,
    };
    if !pem.contains(&format!("-----BEGIN {label}-----")) {
        return Err(malformed("no PEM block of the expected type"));
    }
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|_| malformed("PEM body is not valid base64"))?;
    if !is_complete_der_sequence(&der) {
        return Err(malformed("decoded bytes are not one complete DER sequence"));
    }
    Ok(der)
}

/// Whether `bytes` is exactly one DER SEQUENCE with no trailing slack.
///
/// Catches the realistic corruptions -- truncation, concatenation, a text
/// editor's stray newline inside the body -- without an ASN.1 parser.
fn is_complete_der_sequence(bytes: &[u8]) -> bool {
    if bytes.first() != Some(&0x30) {
        return false;
    }
    let Some(&first_length_byte) = bytes.get(1) else {
        return false;
    };
    let (length, header_len) = if first_length_byte < 0x80 {
        (usize::from(first_length_byte), 2)
    } else {
        let count = usize::from(first_length_byte & 0x7f);
        // Indefinite length (0) is not valid DER; more than four length bytes
        // is a structure far larger than any certificate we mint.
        if count == 0 || count > 4 {
            return false;
        }
        let Some(length_bytes) = bytes.get(2..2 + count) else {
            return false;
        };
        let length = length_bytes
            .iter()
            .fold(0usize, |acc, byte| (acc << 8) | usize::from(*byte));
        (length, 2 + count)
    };
    header_len.checked_add(length) == Some(bytes.len())
}

/// Refuses a private key any account but its owner can read.
///
/// A key the operator's other processes can read is a wider exposure than the
/// module header signs up for, and silently re-tightening it would hide that
/// something already had the chance to read it.
#[cfg(unix)]
fn require_owner_only(path: &Path) -> Result<(), PrivateTlsError> {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = std::fs::metadata(path).map_err(|_| PrivateTlsError::Unreadable {
        path: path.to_path_buf(),
    })?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 == 0 {
        return Ok(());
    }
    Err(PrivateTlsError::InsecureKeyPermissions {
        path: path.to_path_buf(),
        mode,
    })
}

/// No file-mode equivalent to enforce off Unix; the deployment target is a
/// Linux TDX workload, so this is a portability courtesy, not a supported
/// posture.
#[cfg(not(unix))]
fn require_owner_only(_: &Path) -> Result<(), PrivateTlsError> {
    Ok(())
}

/// Creates `path` readable and writable only by its owner, failing if it
/// already exists.
#[cfg(unix)]
fn create_owner_only(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// See [`require_owner_only`]'s non-Unix note: the file is still exclusive,
/// but its mode is whatever the platform defaults to.
#[cfg(not(unix))]
fn create_owner_only(path: &Path) -> std::io::Result<File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// Writes the private key, owner-only, refusing to clobber.
fn write_owner_only(path: &Path, contents: &str) -> Result<(), PrivateTlsError> {
    let unwritable = || PrivateTlsError::Unwritable {
        path: path.to_path_buf(),
    };
    let mut file = create_owner_only(path).map_err(|_| unwritable())?;
    file.write_all(contents.as_bytes())
        .map_err(|_| unwritable())?;
    file.sync_all().map_err(|_| unwritable())
}

/// Writes one of the publishable files.
fn write_public(path: &Path, contents: &str) -> Result<(), PrivateTlsError> {
    std::fs::write(path, contents).map_err(|_| PrivateTlsError::Unwritable {
        path: path.to_path_buf(),
    })
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

/// Why the private surface has no usable identity.
///
/// Every variant names the file it is about, because every variant's remedy is
/// an operator looking at that file. None of them is recoverable by
/// regenerating: a new certificate would break every wallet's pin without
/// telling anyone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PrivateTlsError {
    /// No identity could be minted for this deployment.
    Generate,
    /// A persisted file exists but could not be read.
    Unreadable {
        /// The file that could not be read.
        path: PathBuf,
    },
    /// A file or directory could not be written.
    Unwritable {
        /// The path that could not be written.
        path: PathBuf,
    },
    /// A persisted file exists but is not what it claims to be.
    Malformed {
        /// The file that failed validation.
        path: PathBuf,
        /// What was wrong with it.
        reason: &'static str,
    },
    /// One half of the certificate/key pair is missing.
    Incomplete {
        /// The half that is present.
        present: PathBuf,
        /// The half that is not.
        missing: PathBuf,
    },
    /// The private key is readable by more than its owner.
    InsecureKeyPermissions {
        /// The over-permissive key file.
        path: PathBuf,
        /// Its current mode, masked to the permission bits.
        mode: u32,
    },
    /// The published fingerprint is not the loaded certificate's.
    FingerprintMismatch {
        /// The published record that disagrees.
        path: PathBuf,
    },
}

impl fmt::Display for PrivateTlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Generate => f.write_str("private surface TLS identity could not be generated"),
            Self::Unreadable { path } => write!(
                f,
                "private surface TLS file {} exists but could not be read; refusing to regenerate, because a new certificate would break every pinned wallet without warning",
                path.display()
            ),
            Self::Unwritable { path } => write!(
                f,
                "private surface TLS file {} could not be written",
                path.display()
            ),
            Self::Malformed { path, reason } => write!(
                f,
                "private surface TLS file {} is malformed ({reason}); refusing to regenerate. Inspect it, restore it from backup, or rotate deliberately by deleting both {CERTIFICATE_FILE_NAME} and {PRIVATE_KEY_FILE_NAME} -- which invalidates every wallet's pin",
                path.display()
            ),
            Self::Incomplete { present, missing } => write!(
                f,
                "private surface TLS identity is incomplete: {} is present but {} is missing; refusing to regenerate half an identity. Restore the missing file, or delete both to rotate deliberately",
                present.display(),
                missing.display()
            ),
            Self::InsecureKeyPermissions { path, mode } => write!(
                f,
                "private surface TLS key {} is mode {mode:o}; it must be readable only by its owner (chmod 600)",
                path.display()
            ),
            Self::FingerprintMismatch { path } => write!(
                f,
                "published fingerprint in {} does not match the certificate on disk; one of them is not what operators told wallets to expect",
                path.display()
            ),
        }
    }
}

impl std::error::Error for PrivateTlsError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mints and persists one identity in a fresh directory.
    fn persisted(deployment_dir: &Path) -> Result<PrivateTlsIdentity, PrivateTlsError> {
        PrivateTlsIdentity::load_or_generate(deployment_dir)
    }

    #[test]
    fn a_generated_identity_reports_a_fingerprint_over_the_certificate_it_serves(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let deployment = tempfile::TempDir::new()?;
        let identity = persisted(deployment.path())?;
        let der = validated_der(identity.certificate_pem(), "CERTIFICATE", deployment.path())?;

        assert_eq!(identity.fingerprint(), hex::encode(Sha256::digest(&der)));
        assert_eq!(identity.fingerprint().len(), 64);
        Ok(())
    }

    #[test]
    fn the_private_key_never_appears_in_a_debug_rendering() -> Result<(), Box<dyn std::error::Error>>
    {
        let deployment = tempfile::TempDir::new()?;
        let identity = persisted(deployment.path())?;
        let rendered = format!("{identity:?}");

        assert!(rendered.contains(identity.fingerprint()));
        assert!(!rendered.contains("PRIVATE KEY"));
        assert!(!rendered.contains(&identity.private_key_pem));
        Ok(())
    }

    /// The whole point of persisting: a wallet's pin survives a restart.
    #[test]
    fn a_second_start_reuses_the_persisted_identity() -> Result<(), Box<dyn std::error::Error>> {
        let deployment = tempfile::TempDir::new()?;
        let first = persisted(deployment.path())?;
        let second = persisted(deployment.path())?;

        assert_eq!(first.fingerprint(), second.fingerprint());
        assert_eq!(first.certificate_pem(), second.certificate_pem());
        assert_eq!(first.private_key_pem, second.private_key_pem);
        // And a *different* deployment is a different identity, so the
        // equality above is reuse rather than a constant certificate.
        let elsewhere = tempfile::TempDir::new()?;
        assert_ne!(
            first.fingerprint(),
            persisted(elsewhere.path())?.fingerprint()
        );
        Ok(())
    }

    #[test]
    fn the_persisted_key_is_owner_only() -> Result<(), Box<dyn std::error::Error>> {
        let deployment = tempfile::TempDir::new()?;
        let _identity = persisted(deployment.path())?;

        require_owner_only(&deployment.path().join(PRIVATE_KEY_FILE_NAME))?;
        Ok(())
    }

    /// The dangerous path, closed. Every one of these would, if it silently
    /// regenerated, break every wallet's pin with no signal at all.
    #[test]
    fn a_damaged_identity_fails_closed_rather_than_regenerating(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let deployment = tempfile::TempDir::new()?;
        let original = persisted(deployment.path())?;
        let certificate_path = deployment.path().join(CERTIFICATE_FILE_NAME);
        let key_path = deployment.path().join(PRIVATE_KEY_FILE_NAME);

        std::fs::write(
            &certificate_path,
            "-----BEGIN CERTIFICATE-----\nnot base64 $$\n-----END CERTIFICATE-----\n",
        )?;
        assert!(matches!(
            persisted(deployment.path()),
            Err(PrivateTlsError::Malformed { ref path, .. }) if *path == certificate_path
        ));

        // Well-formed base64 that is not a complete DER structure: the
        // truncation case a plain base64 check would wave through.
        let good = std::fs::read_to_string(&key_path)?;
        let truncated_der = validated_der(&good, "PRIVATE KEY", &key_path)?;
        std::fs::write(
            &certificate_path,
            pem_block("CERTIFICATE", &truncated_der[..truncated_der.len() - 1]),
        )?;
        assert!(matches!(
            persisted(deployment.path()),
            Err(PrivateTlsError::Malformed { .. })
        ));

        // A half-present pair is not a fresh deployment.
        std::fs::remove_file(&certificate_path)?;
        assert!(matches!(
            persisted(deployment.path()),
            Err(PrivateTlsError::Incomplete { .. })
        ));

        // Nothing above wrote a new certificate over the operator's files.
        assert_eq!(
            std::fs::read_to_string(&key_path)?,
            original.private_key_pem
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_key_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let deployment = tempfile::TempDir::new()?;
        let _identity = persisted(deployment.path())?;
        let key_path = deployment.path().join(PRIVATE_KEY_FILE_NAME);
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644))?;

        assert!(matches!(
            persisted(deployment.path()),
            Err(PrivateTlsError::InsecureKeyPermissions { mode: 0o644, .. })
        ));
        Ok(())
    }

    #[test]
    fn publishing_is_idempotent_and_catches_a_disagreeing_record(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let deployment = tempfile::TempDir::new()?;
        let identity = persisted(deployment.path())?;

        let path = identity.publish_fingerprint(deployment.path())?;
        assert_eq!(path, deployment.path().join(FINGERPRINT_FILE_NAME));
        let published = std::fs::read_to_string(&path)?;
        assert_eq!(published, identity.fingerprint_record());
        assert!(published.contains(identity.fingerprint()));
        // Stable across restarts, so nothing per-generation belongs in it.
        assert!(!published.contains("key_epoch"));
        assert!(!published.contains("PRIVATE KEY"));

        // A restart republishes the same record without complaint.
        identity.publish_fingerprint(deployment.path())?;

        std::fs::write(&path, "private_tls_sha256=deadbeef,dns_name:elsewhere\n")?;
        assert!(matches!(
            identity.publish_fingerprint(deployment.path()),
            Err(PrivateTlsError::FingerprintMismatch { .. })
        ));
        Ok(())
    }

    #[test]
    fn the_certificate_names_only_the_surface_and_nothing_per_generation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let deployment = tempfile::TempDir::new()?;
        let identity = persisted(deployment.path())?;
        let der = validated_der(identity.certificate_pem(), "CERTIFICATE", deployment.path())?;

        // The SAN extension stores names as raw IA5 bytes, so an encoded name
        // appears verbatim in the DER. Checked without an X.509 parser on
        // purpose: pulling one in would add a crate to assert one string.
        assert!(contains_subslice(&der, PRIVATE_SURFACE_DNS_NAME.as_bytes()));
        // The certificate outlives many key epochs, so a baked-in one would
        // be wrong from the next restart onward.
        assert!(!contains_subslice(&der, b"key-epoch"));
        Ok(())
    }

    #[test]
    fn incomplete_der_is_rejected_at_every_truncation() {
        // One byte too few, one byte too many, and an empty buffer: the
        // realistic corruptions a base64-only check would accept.
        let sequence = [0x30, 0x03, 0x02, 0x01, 0x2a];
        assert!(is_complete_der_sequence(&sequence));
        assert!(!is_complete_der_sequence(&sequence[..sequence.len() - 1]));
        assert!(!is_complete_der_sequence(
            &[sequence.as_slice(), &[0]].concat()
        ));
        assert!(!is_complete_der_sequence(&[]));
        assert!(!is_complete_der_sequence(&[0x31, 0x00]));
        // Two-byte long form, correctly covered.
        let long_form = [&[0x30, 0x82, 0x00, 0x02][..], &[0x05, 0x00][..]].concat();
        assert!(is_complete_der_sequence(&long_form));
        assert!(!is_complete_der_sequence(&long_form[..long_form.len() - 1]));
    }

    #[test]
    fn pem_blocks_wrap_at_the_line_width_and_round_trip() -> Result<(), Box<dyn std::error::Error>>
    {
        // A DER SEQUENCE whose declared length covers its body, so the block
        // round-trips through the same validation persisted files face.
        let mut der = vec![0x30, 0x82, 0x01, 0x2c];
        der.extend((0u16..300).map(|byte| byte as u8));
        let block = pem_block("CERTIFICATE", &der);

        assert!(block.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(block.ends_with("-----END CERTIFICATE-----\n"));
        for line in block.lines().skip(1).take_while(|l| !l.starts_with("---")) {
            assert!(line.len() <= PEM_LINE_WIDTH);
        }
        assert_eq!(
            validated_der(&block, "CERTIFICATE", Path::new("test"))?,
            der
        );
        Ok(())
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }
}
