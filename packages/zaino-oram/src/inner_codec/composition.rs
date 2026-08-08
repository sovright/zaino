//! Production composition of the private runtime's security providers.
//!
//! Everything below this module exists as an injected trait parameter so each
//! provider stays testable in isolation. This module is where the concrete
//! choices are made once: XChaCha20-Poly1305 for envelopes, continuation
//! tokens, and replay-journal records; the operating-system generator for
//! nonces and lease bindings; the host wall clock for the round's time
//! observation; and a crash-durable local replay journal.
//!
//! What this composition does not establish, and deliberately leaves to its
//! caller or to a later slice: key custody (the four keys arrive already
//! derived), trusted time, and rollback resistance. The replay journal is
//! crash-durable against process restart but has no external freshness
//! witness, so a host able to restore an older journal directory can replay
//! against it. `ReplaySnapshotCoordinator` is the seam for that hardening; it
//! requires an authority outside the host, which is an attestation decision
//! rather than a code one.

use std::path::PathBuf;

use blake2::{Blake2s256, Digest};
use zeroize::Zeroizing;

use crate::{
    profile::{PrivacyProfile, PROFILE_ID_BYTES},
    xchacha20::KEY_BYTES,
};

use super::{
    replay_journal::{
        record_protector, OsJournalRecordNonces, ReplayJournalProtectionContext,
        ReplayJournalRecordProtector, ReplayJournalStore,
    },
    security_owner::{
        xchacha20_security_lease, ActiveSecurityLease, OsEntropy, OwnedRoundMaterialSource,
        SecurityLeaseIdentity, SystemRoundClock,
    },
    EnvelopeProtector, UniformExternalFailure,
};
use crate::{continuation_token::ContinuationTokenProtector, profile::CompiledQueryShape};

const PROTECTION_CONTEXT_DIGEST_BYTES: usize = 32;
const PROTECTION_CONTEXT_DOMAIN: &[u8] = b"zaino-oram/replay-journal/protection-context/v1";
const PROTECTION_CONTEXT_VERSION: u16 = 1;

/// The four long-lived keys one runtime owns.
///
/// They arrive already derived: this module fixes how each is used, not where
/// it comes from. Each is separately owned so a future custody boundary can
/// rotate them independently, and each is `Zeroizing` so the caller's copy is
/// cleared once the protector has taken it.
pub(super) struct RuntimeKeyMaterial {
    pub(super) request_key: Zeroizing<[u8; KEY_BYTES]>,
    pub(super) response_key: Zeroizing<[u8; KEY_BYTES]>,
    pub(super) token_key: Zeroizing<[u8; KEY_BYTES]>,
    pub(super) replay_journal_key: Zeroizing<[u8; KEY_BYTES]>,
}

/// Deployment identity and durable locations that must survive a restart.
///
/// `owner_generation` and `key_epoch` separate one owner's state from its
/// predecessor's; reusing a pair against a journal written by an earlier owner
/// is what the journal's identity checks exist to refuse.
pub(super) struct RuntimeDeployment {
    pub(super) service_namespace_id: [u8; 16],
    pub(super) owner_generation: u64,
    pub(super) key_epoch: u64,
    pub(super) replay_journal_root: PathBuf,
}

/// Binds the journal's record protection to one exact deployment and profile.
///
/// Records sealed for one profile or owner generation cannot authenticate
/// under another, so a journal directory carried across either boundary fails
/// closed at the first record rather than being silently reinterpreted.
fn protection_context(
    deployment: &RuntimeDeployment,
    profile_id: &[u8; PROFILE_ID_BYTES],
) -> ReplayJournalProtectionContext {
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, PROTECTION_CONTEXT_DOMAIN);
    Digest::update(&mut hasher, PROTECTION_CONTEXT_VERSION.to_be_bytes());
    Digest::update(&mut hasher, profile_id);
    Digest::update(&mut hasher, deployment.service_namespace_id);
    Digest::update(&mut hasher, deployment.owner_generation.to_be_bytes());
    Digest::update(&mut hasher, deployment.key_epoch.to_be_bytes());
    let digest = hasher.finalize();
    let mut binding = [0; PROTECTION_CONTEXT_DIGEST_BYTES];
    binding.copy_from_slice(&digest);
    ReplayJournalProtectionContext::new(binding)
}

/// Opens the crash-durable replay journal for one deployment and profile.
pub(super) fn open_replay_journal(
    deployment: &RuntimeDeployment,
    profile: &PrivacyProfile,
    replay_journal_key: Zeroizing<[u8; KEY_BYTES]>,
) -> Result<
    ReplayJournalStore<impl super::replay_journal::ReplayJournalRecordProtector>,
    UniformExternalFailure,
> {
    let protector = record_protector(replay_journal_key, OsJournalRecordNonces);
    ReplayJournalStore::open(
        deployment.replay_journal_root.clone(),
        profile,
        protection_context(deployment, profile.profile_id()),
        protector,
    )
    .map_err(|_| UniformExternalFailure)
}

/// Composes one runtime's complete security lease.
///
/// The four providers are fixed here: XChaCha20-Poly1305 envelope and
/// continuation-token protection, the crash-durable replay journal, and round
/// material drawn from the operating-system generator and the host clock. The
/// lease's two secret bindings are minted fresh, so a restart never resumes a
/// predecessor's session or security epoch even against the same journal.
pub(super) fn security_lease<const RESPONSE_SLOTS: usize, const ENVELOPE_BYTES: usize>(
    deployment: &RuntimeDeployment,
    shape: CompiledQueryShape<RESPONSE_SLOTS, ENVELOPE_BYTES>,
    keys: RuntimeKeyMaterial,
) -> Result<
    ActiveSecurityLease<
        impl EnvelopeProtector,
        impl ContinuationTokenProtector,
        ReplayJournalStore<impl ReplayJournalRecordProtector>,
        OwnedRoundMaterialSource<OsEntropy, SystemRoundClock>,
    >,
    UniformExternalFailure,
> {
    let RuntimeKeyMaterial {
        request_key,
        response_key,
        token_key,
        replay_journal_key,
    } = keys;
    let replay_guard = open_replay_journal(deployment, shape.profile(), replay_journal_key)?;
    let identity = SecurityLeaseIdentity::mint(
        deployment.key_epoch,
        deployment.service_namespace_id,
        deployment.owner_generation,
        &mut OsEntropy,
    )?;
    Ok(xchacha20_security_lease(
        shape,
        identity,
        request_key,
        response_key,
        token_key,
        replay_guard,
        OwnedRoundMaterialSource::new(OsEntropy, SystemRoundClock),
    ))
}

/// Builds one process-lifetime runtime owner over a composed security lease.
///
/// The returned owner has no serving epoch yet and refuses every request until
/// one is published, because the epoch is captured from a live chain subscriber
/// rather than assumed. That first refresh is the caller's step; the owner's
/// job is to make sure no request is served from an epoch that was never
/// pinned.
#[cfg(feature = "corpus-zaino")]
#[cfg_attr(
    test,
    expect(
        dead_code,
        reason = "the composition root lands before the zainod-oram service that binds a \
                  listener to it; constructing one here would need a BlockchainSource stub \
                  that exercises nothing, since only refresh touches the source"
    )
)]
pub(super) fn finalized_runtime_owner<
    Source,
    const RESPONSE_SLOTS: usize,
    const ENVELOPE_BYTES: usize,
    const RECENT_SNAPSHOT_SLOTS: usize,
>(
    deployment: &RuntimeDeployment,
    network: super::super::canonical_chain::CanonicalNetwork,
    schema_version: u32,
    projection_epoch: u64,
    shape: CompiledQueryShape<RESPONSE_SLOTS, ENVELOPE_BYTES>,
    keys: RuntimeKeyMaterial,
) -> Result<
    super::runtime::FinalizedRuntimeOwner<
        Source,
        impl EnvelopeProtector,
        impl ContinuationTokenProtector,
        ReplayJournalStore<impl ReplayJournalRecordProtector>,
        OwnedRoundMaterialSource<OsEntropy, SystemRoundClock>,
        RESPONSE_SLOTS,
        ENVELOPE_BYTES,
        RECENT_SNAPSHOT_SLOTS,
    >,
    UniformExternalFailure,
>
where
    Source: zaino_state::BlockchainSource,
{
    let security = security_lease(deployment, shape, keys)?;
    super::runtime::FinalizedRuntimeOwner::new(
        network,
        schema_version,
        projection_epoch,
        shape,
        security,
    )
    .map_err(|_| UniformExternalFailure)
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::profile::{
        mainnet_utxo_history_profile, MAINNET_ENVELOPE_BYTES, MAINNET_QUERY_SLOTS,
    };

    type FixtureResult = Result<(), Box<dyn std::error::Error>>;
    type MainnetShape = CompiledQueryShape<MAINNET_QUERY_SLOTS, MAINNET_ENVELOPE_BYTES>;

    fn keys() -> RuntimeKeyMaterial {
        RuntimeKeyMaterial {
            request_key: Zeroizing::new([0x11; KEY_BYTES]),
            response_key: Zeroizing::new([0x22; KEY_BYTES]),
            token_key: Zeroizing::new([0x33; KEY_BYTES]),
            replay_journal_key: Zeroizing::new([0x44; KEY_BYTES]),
        }
    }

    fn deployment(root: &TempDir) -> RuntimeDeployment {
        RuntimeDeployment {
            service_namespace_id: [0x55; 16],
            owner_generation: 1,
            key_epoch: 1,
            replay_journal_root: root.path().join("replay"),
        }
    }

    fn mainnet_shape() -> Result<MainnetShape, Box<dyn std::error::Error>> {
        Ok(CompiledQueryShape::new(mainnet_utxo_history_profile()?)?)
    }

    #[test]
    fn a_lease_composes_over_the_mainnet_profile_and_a_fresh_journal() -> FixtureResult {
        let root = TempDir::new()?;

        let lease = security_lease(&deployment(&root), mainnet_shape()?, keys())
            .map_err(|_| "the mainnet lease composes")?;

        assert_eq!(lease.key_epoch(), 1);
        assert_eq!(
            lease.profile_id(),
            mainnet_utxo_history_profile()?.profile_id()
        );
        Ok(())
    }

    /// Two leases over the same journal directory must not share a session
    /// binding: it is minted per lease, so a restart cannot resume its
    /// predecessor's identity even against identical durable state.
    #[test]
    fn each_lease_mints_a_distinct_session_binding() -> FixtureResult {
        let root = TempDir::new()?;
        let deployment = deployment(&root);

        let first = security_lease(&deployment, mainnet_shape()?, keys())
            .map_err(|_| "the first lease composes")?;
        let first_session = first.session_binding();
        drop(first);
        let second = security_lease(&deployment, mainnet_shape()?, keys())
            .map_err(|_| "the second lease composes over the existing journal")?;

        assert_ne!(first_session, second.session_binding());
        Ok(())
    }

    /// The journal's record protection binds the deployment, so a directory
    /// carried to a different owner generation cannot be reopened under it.
    #[test]
    fn the_protection_context_separates_owner_generations() -> FixtureResult {
        let root = TempDir::new()?;
        let profile = mainnet_utxo_history_profile()?;
        let first = deployment(&root);
        let mut second = deployment(&root);
        second.owner_generation = 2;

        assert_ne!(
            protection_context(&first, profile.profile_id()),
            protection_context(&second, profile.profile_id())
        );
        Ok(())
    }
}
