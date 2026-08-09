//! Crate-internal fixed private-query request and response codec.
//!
//! The codec pins canonical big-endian fields inside one compile-time fixed
//! envelope and injects a whole-envelope protection interface. It supplies no
//! production protector or nonce owner. Its private listener-free runtime child
//! composes the codec with the logical engine and fixed phase recorder; no
//! network, production AEAD, or physical fixed-work claim is made.
//!
//! Deviation from the named `to_wire` / `try_from_wire` convention: this
//! format has no intermediate proto or wire structs. Codec-local helpers write
//! business values directly into one fixed buffer and return business values
//! only after protection and canonical validation. Keeping offsets and parsing
//! here avoids exposing framing details on the business types; no `From` or
//! `TryFrom` boundary conversion is used.

use std::{fmt, marker::PhantomData};

use blake2::{Blake2s256, Digest};

use crate::{
    continuation_token::{
        ContinuationProtectionContext, ContinuationToken, CONTINUATION_CONTEXT_BYTES,
        CONTINUATION_TOKEN_BYTES,
    },
    envelope::FixedEnvelope,
    profile::{all_zero, CompiledQueryShape, PROFILE_ID_BYTES},
    protection::{AuthenticationDecision, ProtectionUnavailable},
    records::{
        AddressKey, QueryOutcome, TransparentUtxo, UtxoQuery, UtxoResultPage, ADDRESS_KEY_BYTES,
        TRANSPARENT_SCRIPT_CAPACITY, TXID_BYTES,
    },
};

mod composition;
mod replay_journal;
mod runtime;
mod security_owner;
mod security_state_binding;
mod security_state_store;
mod xchacha20;

// The crate's one public composition seam. It lives inside `inner_codec`
// rather than beside it because composing a runtime means naming the
// protector, lease, and journal types this module keeps private; hoisting it
// out would mean widening all of them, which is exactly the hiding the codec
// is built around. Only the opaque `impl Trait` it returns leaves the crate.
#[cfg(feature = "corpus-zaino")]
pub(super) mod private_service;

const FORMAT_VERSION: u16 = 1;
const U16_BYTES: usize = 2;
const U32_BYTES: usize = 4;
const U64_BYTES: usize = 8;
const ENVELOPE_NONCE_BYTES: usize = 24;
const ENVELOPE_AUTHENTICATION_BYTES: usize = 16;
const ENVELOPE_OVERHEAD_BYTES: usize = ENVELOPE_NONCE_BYTES + ENVELOPE_AUTHENTICATION_BYTES;
const SESSION_BINDING_BYTES: usize = 32;
const BLOCK_HASH_BYTES: usize = 32;
const CHECKPOINT_BYTES: usize =
    1 + U32_BYTES + BLOCK_HASH_BYTES + U32_BYTES + U64_BYTES + U64_BYTES;
const QUERY_BYTES: usize = ADDRESS_KEY_BYTES + U32_BYTES + 1;
const UTXO_BYTES: usize =
    TXID_BYTES + U32_BYTES + U64_BYTES + U32_BYTES + 1 + TRANSPARENT_SCRIPT_CAPACITY;
const RESULT_SLOT_BYTES: usize = 1 + UTXO_BYTES;

const VERSION_START: usize = 0;
const DIRECTION_START: usize = VERSION_START + U16_BYTES;
const PROFILE_ID_START: usize = DIRECTION_START + 1;
const CHECKPOINT_START: usize = PROFILE_ID_START + PROFILE_ID_BYTES;

const REQUEST_QUERY_START: usize = CHECKPOINT_START + CHECKPOINT_BYTES;
const REQUEST_FLAGS_START: usize = REQUEST_QUERY_START + QUERY_BYTES;
const REQUEST_TOKEN_START: usize = REQUEST_FLAGS_START + 1;
const REQUEST_SESSION_BINDING_START: usize = REQUEST_TOKEN_START + CONTINUATION_TOKEN_BYTES;
const REQUEST_BODY_BYTES: usize = REQUEST_SESSION_BINDING_START + SESSION_BINDING_BYTES;

const RESPONSE_OUTCOME_START: usize = CHECKPOINT_START + CHECKPOINT_BYTES;
const RESPONSE_SLOTS_START: usize = RESPONSE_OUTCOME_START + 1;

const REQUEST_FLAG_CONTINUATION: u8 = 1 << 0;
const RESPONSE_FLAG_HAS_MORE: u8 = 1 << 0;
const QUERY_FLAG_DOMAIN_VALID: u8 = 1 << 0;
const QUERY_DIGEST_DOMAIN: &[u8] = b"zaino-oram/utxo-query/v1";
const UTXO_QUERY_METHOD_TAG: u8 = 1;

type EnvelopePartsMut<'a> = (
    &'a mut [u8; ENVELOPE_NONCE_BYTES],
    &'a mut [u8],
    &'a mut [u8; ENVELOPE_AUTHENTICATION_BYTES],
);

/// One network tag carried inside the protected checkpoint.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PrivateNetwork {
    Mainnet,
    Testnet,
    Regtest,
}

impl PrivateNetwork {
    const fn tag(self) -> u8 {
        match self {
            Self::Mainnet => 0,
            Self::Testnet => 1,
            Self::Regtest => 2,
        }
    }

    const fn try_from_tag(tag: u8) -> Result<Self, InnerCodecError> {
        match tag {
            0 => Ok(Self::Mainnet),
            1 => Ok(Self::Testnet),
            2 => Ok(Self::Regtest),
            _ => Err(InnerCodecError::UnknownNetwork),
        }
    }
}

impl fmt::Debug for PrivateNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateNetwork([REDACTED])")
    }
}

/// Fixed public-chain and projection identity protected in every round.
#[derive(Clone, Copy, PartialEq, Eq)]
struct PrivateQueryCheckpoint {
    network: PrivateNetwork,
    height: u32,
    /// Canonical 32-byte block hash in RPC/display byte order.
    block_hash_display: [u8; BLOCK_HASH_BYTES],
    schema_version: u32,
    /// Volatile projection lifecycle; rolls on every restart/rebuild.
    projection_epoch: u64,
    key_epoch: u64,
}

impl PrivateQueryCheckpoint {
    const fn new(
        network: PrivateNetwork,
        height: u32,
        block_hash_display: [u8; BLOCK_HASH_BYTES],
        schema_version: u32,
        projection_epoch: u64,
        key_epoch: u64,
    ) -> Self {
        Self {
            network,
            height,
            block_hash_display,
            schema_version,
            projection_epoch,
            key_epoch,
        }
    }
}

impl fmt::Debug for PrivateQueryCheckpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateQueryCheckpoint { ..REDACTED.. }")
    }
}

/// One typed request before whole-envelope authenticated protection.
#[derive(Clone, PartialEq, Eq)]
struct PrivateQueryRequest {
    checkpoint: PrivateQueryCheckpoint,
    query: UtxoQuery,
    continuation: Option<ContinuationToken>,
}

impl PrivateQueryRequest {
    const fn new(
        checkpoint: PrivateQueryCheckpoint,
        query: UtxoQuery,
        continuation: Option<ContinuationToken>,
    ) -> Self {
        Self {
            checkpoint,
            query,
            continuation,
        }
    }

    const fn query(&self) -> &UtxoQuery {
        &self.query
    }
}

impl fmt::Debug for PrivateQueryRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateQueryRequest { ..REDACTED.. }")
    }
}

/// One typed response before whole-envelope authenticated protection.
#[derive(Clone, PartialEq, Eq)]
struct PrivateQueryResponse<const RESPONSE_SLOTS: usize> {
    checkpoint: PrivateQueryCheckpoint,
    page: UtxoResultPage<RESPONSE_SLOTS>,
    has_more: bool,
    continuation: Option<ContinuationToken>,
}

impl<const RESPONSE_SLOTS: usize> PrivateQueryResponse<RESPONSE_SLOTS> {
    fn new(
        checkpoint: PrivateQueryCheckpoint,
        page: UtxoResultPage<RESPONSE_SLOTS>,
        has_more: bool,
        continuation: Option<ContinuationToken>,
    ) -> Result<Self, InnerCodecError> {
        validate_response_shape(&page, has_more, continuation.as_ref())?;
        Ok(Self {
            checkpoint,
            page,
            has_more,
            continuation,
        })
    }
}

impl<const RESPONSE_SLOTS: usize> fmt::Debug for PrivateQueryResponse<RESPONSE_SLOTS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateQueryResponse")
            .field("slots", &RESPONSE_SLOTS)
            .finish_non_exhaustive()
    }
}

/// Protection injected around the complete fixed envelope body.
///
/// A crate-internal XChaCha20-Poly1305 primitive is available, but no service
/// yet owns its keys, session establishment, or nonce lifecycle. Any selected
/// implementation must bind the complete [`EnvelopeProtectionContext`] as
/// associated data or through domain-separated key derivation before releasing
/// plaintext. The codec never treats the deterministic test implementation as
/// cryptographic evidence.
trait EnvelopeProtector {
    /// Protects `body`, or reports that no protected output can be produced.
    fn seal(
        &self,
        context: &EnvelopeProtectionContext,
        nonce: &[u8; ENVELOPE_NONCE_BYTES],
        body: &mut [u8],
    ) -> Result<[u8; ENVELOPE_AUTHENTICATION_BYTES], ProtectionUnavailable>;

    /// Authenticates `body` without exposing plaintext on rejection or error.
    fn open(
        &self,
        context: &EnvelopeProtectionContext,
        nonce: &[u8; ENVELOPE_NONCE_BYTES],
        body: &mut [u8],
        authentication: &[u8; ENVELOPE_AUTHENTICATION_BYTES],
    ) -> Result<AuthenticationDecision, ProtectionUnavailable>;
}

fn xchacha20_envelope_protector(
    request_key: zeroize::Zeroizing<[u8; crate::xchacha20::KEY_BYTES]>,
    response_key: zeroize::Zeroizing<[u8; crate::xchacha20::KEY_BYTES]>,
) -> impl EnvelopeProtector {
    xchacha20::envelope_protector(request_key, response_key)
}

fn require_authentication(
    decision: Result<AuthenticationDecision, ProtectionUnavailable>,
) -> Result<(), InnerCodecError> {
    match decision {
        Ok(AuthenticationDecision::Accepted) => Ok(()),
        Ok(AuthenticationDecision::Rejected) => Err(InnerCodecError::AuthenticationFailed),
        Err(ProtectionUnavailable) => Err(InnerCodecError::ProtectionUnavailable),
    }
}

/// Public context that must be cryptographically bound outside the protected
/// body so profile/session cross-replays fail before plaintext parsing.
#[derive(Clone, Copy, PartialEq, Eq)]
struct EnvelopeProtectionContext {
    format_version: u16,
    direction: EnvelopeDirection,
    profile_id: [u8; PROFILE_ID_BYTES],
    session_binding: [u8; SESSION_BINDING_BYTES],
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EnvelopeDirection {
    Request,
    Response,
}

impl EnvelopeDirection {
    const fn tag(self) -> u8 {
        match self {
            Self::Request => 1,
            Self::Response => 2,
        }
    }
}

/// A codec sealed to one validated profile, page shape, and session binding.
struct PrivateQueryCodec<const RESPONSE_SLOTS: usize, const ENVELOPE_BYTES: usize> {
    profile_id: [u8; PROFILE_ID_BYTES],
    session_binding: [u8; SESSION_BINDING_BYTES],
    shape: PhantomData<CompiledQueryShape<RESPONSE_SLOTS, ENVELOPE_BYTES>>,
}

impl<const RESPONSE_SLOTS: usize, const ENVELOPE_BYTES: usize>
    PrivateQueryCodec<RESPONSE_SLOTS, ENVELOPE_BYTES>
{
    fn new(
        shape: &CompiledQueryShape<RESPONSE_SLOTS, ENVELOPE_BYTES>,
        session_binding: [u8; SESSION_BINDING_BYTES],
    ) -> Result<Self, InnerCodecError> {
        if all_zero(&session_binding) {
            return Err(InnerCodecError::ZeroSessionBinding);
        }
        let required = required_envelope_bytes(RESPONSE_SLOTS)?;
        if ENVELOPE_BYTES < required {
            return Err(InnerCodecError::EnvelopeCapacityTooSmall {
                required,
                available: ENVELOPE_BYTES,
            });
        }
        Ok(Self {
            profile_id: *shape.profile().profile_id(),
            session_binding,
            shape: PhantomData,
        })
    }

    const fn protection_context(&self, direction: EnvelopeDirection) -> EnvelopeProtectionContext {
        EnvelopeProtectionContext {
            format_version: FORMAT_VERSION,
            direction,
            profile_id: self.profile_id,
            session_binding: self.session_binding,
        }
    }

    fn continuation_protection_context(
        &self,
        checkpoint: &PrivateQueryCheckpoint,
    ) -> Result<ContinuationProtectionContext, InnerCodecError> {
        if CHECKPOINT_BYTES + SESSION_BINDING_BYTES != CONTINUATION_CONTEXT_BYTES {
            return Err(InnerCodecError::LayoutInvariant);
        }
        let mut bytes = [0; CONTINUATION_CONTEXT_BYTES];
        encode_checkpoint(&mut bytes, 0, checkpoint)?;
        write_array(&mut bytes, CHECKPOINT_BYTES, &self.session_binding)?;
        Ok(ContinuationProtectionContext::new(bytes))
    }

    fn encode_request<P>(
        &self,
        request: &PrivateQueryRequest,
        nonce: [u8; ENVELOPE_NONCE_BYTES],
        protector: &P,
    ) -> Result<FixedEnvelope<ENVELOPE_BYTES>, InnerCodecError>
    where
        P: EnvelopeProtector,
    {
        let mut bytes = [0; ENVELOPE_BYTES];
        let (outer_nonce, body, authentication) = split_envelope_mut(&mut bytes)?;
        *outer_nonce = nonce;
        self.encode_header(body, EnvelopeDirection::Request, &request.checkpoint)?;
        encode_query(body, REQUEST_QUERY_START, request.query())?;
        encode_optional_token(
            body,
            REQUEST_FLAGS_START,
            REQUEST_TOKEN_START,
            REQUEST_FLAG_CONTINUATION,
            request.continuation.as_ref(),
        )?;
        write_array(body, REQUEST_SESSION_BINDING_START, &self.session_binding)?;
        ensure_zero(body, REQUEST_BODY_BYTES)?;
        *authentication = protector
            .seal(
                &self.protection_context(EnvelopeDirection::Request),
                outer_nonce,
                body,
            )
            .map_err(|_| InnerCodecError::ProtectionUnavailable)?;
        Ok(FixedEnvelope::from_array(bytes))
    }

    fn decode_request<P>(
        &self,
        envelope: &FixedEnvelope<ENVELOPE_BYTES>,
        protector: &P,
    ) -> Result<PrivateQueryRequest, InnerCodecError>
    where
        P: EnvelopeProtector,
    {
        self.decode_request_with_nonce(envelope, protector)
            .map(|(request, _nonce)| request)
    }

    fn decode_request_with_nonce<P>(
        &self,
        envelope: &FixedEnvelope<ENVELOPE_BYTES>,
        protector: &P,
    ) -> Result<(PrivateQueryRequest, [u8; ENVELOPE_NONCE_BYTES]), InnerCodecError>
    where
        P: EnvelopeProtector,
    {
        let mut bytes = *envelope.as_bytes();
        let (nonce, body, authentication) = split_envelope_mut(&mut bytes)?;
        require_authentication(protector.open(
            &self.protection_context(EnvelopeDirection::Request),
            nonce,
            body,
            authentication,
        ))?;
        let authenticated_nonce = *nonce;
        let checkpoint = self.decode_header(body, EnvelopeDirection::Request)?;
        let query = decode_query(body, REQUEST_QUERY_START)?;
        let continuation = decode_optional_token(
            body,
            REQUEST_FLAGS_START,
            REQUEST_TOKEN_START,
            REQUEST_FLAG_CONTINUATION,
        )?;
        validate_binding(body, REQUEST_SESSION_BINDING_START, &self.session_binding)?;
        ensure_zero(body, REQUEST_BODY_BYTES)?;
        Ok((
            PrivateQueryRequest::new(checkpoint, query, continuation),
            authenticated_nonce,
        ))
    }

    fn query_digest(&self, query: &UtxoQuery) -> [u8; 32] {
        let mut hasher = Blake2s256::new();
        Digest::update(&mut hasher, QUERY_DIGEST_DOMAIN);
        Digest::update(&mut hasher, [UTXO_QUERY_METHOD_TAG]);
        Digest::update(&mut hasher, query.address_key().as_bytes());
        Digest::update(&mut hasher, query.minimum_height().to_be_bytes());
        Digest::update(&mut hasher, [u8::from(query.domain_valid())]);
        let digest = Digest::finalize(hasher);
        let mut query_digest = [0; 32];
        query_digest.copy_from_slice(&digest);
        query_digest
    }

    fn encode_response<P>(
        &self,
        response: &PrivateQueryResponse<RESPONSE_SLOTS>,
        nonce: [u8; ENVELOPE_NONCE_BYTES],
        protector: &P,
    ) -> Result<FixedEnvelope<ENVELOPE_BYTES>, InnerCodecError>
    where
        P: EnvelopeProtector,
    {
        validate_response_shape(
            &response.page,
            response.has_more,
            response.continuation.as_ref(),
        )?;
        let layout = response_layout(RESPONSE_SLOTS)?;
        let mut bytes = [0; ENVELOPE_BYTES];
        let (outer_nonce, body, authentication) = split_envelope_mut(&mut bytes)?;
        *outer_nonce = nonce;
        self.encode_header(body, EnvelopeDirection::Response, &response.checkpoint)?;
        write_byte(
            body,
            RESPONSE_OUTCOME_START,
            outcome_tag(response.page.outcome()),
        )?;
        encode_result_slots(body, RESPONSE_SLOTS_START, response.page.slots())?;
        encode_optional_token(
            body,
            layout.flags,
            layout.token,
            RESPONSE_FLAG_HAS_MORE,
            response.continuation.as_ref(),
        )?;
        write_array(body, layout.session_binding, &self.session_binding)?;
        ensure_zero(body, layout.body_end)?;
        *authentication = protector
            .seal(
                &self.protection_context(EnvelopeDirection::Response),
                outer_nonce,
                body,
            )
            .map_err(|_| InnerCodecError::ProtectionUnavailable)?;
        Ok(FixedEnvelope::from_array(bytes))
    }

    fn decode_response<P>(
        &self,
        envelope: &FixedEnvelope<ENVELOPE_BYTES>,
        protector: &P,
    ) -> Result<PrivateQueryResponse<RESPONSE_SLOTS>, InnerCodecError>
    where
        P: EnvelopeProtector,
    {
        let layout = response_layout(RESPONSE_SLOTS)?;
        let mut bytes = *envelope.as_bytes();
        let (nonce, body, authentication) = split_envelope_mut(&mut bytes)?;
        require_authentication(protector.open(
            &self.protection_context(EnvelopeDirection::Response),
            nonce,
            body,
            authentication,
        ))?;
        let checkpoint = self.decode_header(body, EnvelopeDirection::Response)?;
        let outcome = outcome_from_tag(read_byte(body, RESPONSE_OUTCOME_START)?)?;
        let page = decode_result_page(body, RESPONSE_SLOTS_START, outcome)?;
        let continuation =
            decode_optional_token(body, layout.flags, layout.token, RESPONSE_FLAG_HAS_MORE)?;
        let flags = read_byte(body, layout.flags)?;
        let has_more = flags & RESPONSE_FLAG_HAS_MORE != 0;
        validate_binding(body, layout.session_binding, &self.session_binding)?;
        ensure_zero(body, layout.body_end)?;
        PrivateQueryResponse::new(checkpoint, page, has_more, continuation)
    }

    fn encode_header(
        &self,
        body: &mut [u8],
        direction: EnvelopeDirection,
        checkpoint: &PrivateQueryCheckpoint,
    ) -> Result<(), InnerCodecError> {
        write_array(body, VERSION_START, &FORMAT_VERSION.to_be_bytes())?;
        write_byte(body, DIRECTION_START, direction.tag())?;
        write_array(body, PROFILE_ID_START, &self.profile_id)?;
        encode_checkpoint(body, CHECKPOINT_START, checkpoint)
    }

    fn decode_header(
        &self,
        body: &[u8],
        direction: EnvelopeDirection,
    ) -> Result<PrivateQueryCheckpoint, InnerCodecError> {
        let version = u16::from_be_bytes(read_array(body, VERSION_START)?);
        if version != FORMAT_VERSION {
            return Err(InnerCodecError::VersionMismatch);
        }
        if read_byte(body, DIRECTION_START)? != direction.tag() {
            return Err(InnerCodecError::DirectionMismatch);
        }
        if read_array::<PROFILE_ID_BYTES>(body, PROFILE_ID_START)? != self.profile_id {
            return Err(InnerCodecError::ProfileMismatch);
        }
        decode_checkpoint(body, CHECKPOINT_START)
    }
}

#[derive(Clone, Copy)]
struct ResponseLayout {
    flags: usize,
    token: usize,
    session_binding: usize,
    body_end: usize,
}

fn response_layout(response_slots: usize) -> Result<ResponseLayout, InnerCodecError> {
    let slots_bytes = response_slots
        .checked_mul(RESULT_SLOT_BYTES)
        .ok_or(InnerCodecError::LayoutOverflow)?;
    let flags = RESPONSE_SLOTS_START
        .checked_add(slots_bytes)
        .ok_or(InnerCodecError::LayoutOverflow)?;
    let token = flags
        .checked_add(1)
        .ok_or(InnerCodecError::LayoutOverflow)?;
    let session_binding = token
        .checked_add(CONTINUATION_TOKEN_BYTES)
        .ok_or(InnerCodecError::LayoutOverflow)?;
    let body_end = session_binding
        .checked_add(SESSION_BINDING_BYTES)
        .ok_or(InnerCodecError::LayoutOverflow)?;
    Ok(ResponseLayout {
        flags,
        token,
        session_binding,
        body_end,
    })
}

fn required_envelope_bytes(response_slots: usize) -> Result<usize, InnerCodecError> {
    let body = REQUEST_BODY_BYTES.max(response_layout(response_slots)?.body_end);
    body.checked_add(ENVELOPE_OVERHEAD_BYTES)
        .ok_or(InnerCodecError::LayoutOverflow)
}

fn split_envelope_mut<const N: usize>(
    bytes: &mut [u8; N],
) -> Result<EnvelopePartsMut<'_>, InnerCodecError> {
    let body_bytes = N
        .checked_sub(ENVELOPE_OVERHEAD_BYTES)
        .ok_or(InnerCodecError::LayoutInvariant)?;
    let (nonce, remainder) = bytes.split_at_mut(ENVELOPE_NONCE_BYTES);
    let (body, authentication) = remainder.split_at_mut(body_bytes);
    let nonce = nonce
        .try_into()
        .map_err(|_| InnerCodecError::LayoutInvariant)?;
    let authentication = authentication
        .try_into()
        .map_err(|_| InnerCodecError::LayoutInvariant)?;
    Ok((nonce, body, authentication))
}

fn encode_checkpoint(
    body: &mut [u8],
    start: usize,
    checkpoint: &PrivateQueryCheckpoint,
) -> Result<(), InnerCodecError> {
    write_byte(body, start, checkpoint.network.tag())?;
    let height = offset(start, 1)?;
    write_array(body, height, &checkpoint.height.to_be_bytes())?;
    let block_hash = offset(height, U32_BYTES)?;
    write_array(body, block_hash, &checkpoint.block_hash_display)?;
    let schema_version = offset(block_hash, BLOCK_HASH_BYTES)?;
    write_array(
        body,
        schema_version,
        &checkpoint.schema_version.to_be_bytes(),
    )?;
    let projection_epoch = offset(schema_version, U32_BYTES)?;
    write_array(
        body,
        projection_epoch,
        &checkpoint.projection_epoch.to_be_bytes(),
    )?;
    let key_epoch = offset(projection_epoch, U64_BYTES)?;
    write_array(body, key_epoch, &checkpoint.key_epoch.to_be_bytes())
}

fn decode_checkpoint(body: &[u8], start: usize) -> Result<PrivateQueryCheckpoint, InnerCodecError> {
    let network = PrivateNetwork::try_from_tag(read_byte(body, start)?)?;
    let height = offset(start, 1)?;
    let block_hash = offset(height, U32_BYTES)?;
    let schema_version = offset(block_hash, BLOCK_HASH_BYTES)?;
    let projection_epoch = offset(schema_version, U32_BYTES)?;
    let key_epoch = offset(projection_epoch, U64_BYTES)?;
    Ok(PrivateQueryCheckpoint::new(
        network,
        u32::from_be_bytes(read_array(body, height)?),
        read_array(body, block_hash)?,
        u32::from_be_bytes(read_array(body, schema_version)?),
        u64::from_be_bytes(read_array(body, projection_epoch)?),
        u64::from_be_bytes(read_array(body, key_epoch)?),
    ))
}

fn encode_query(body: &mut [u8], start: usize, query: &UtxoQuery) -> Result<(), InnerCodecError> {
    write_array(body, start, query.address_key().as_bytes())?;
    let minimum_height = offset(start, ADDRESS_KEY_BYTES)?;
    write_array(body, minimum_height, &query.minimum_height().to_be_bytes())?;
    let flags = offset(minimum_height, U32_BYTES)?;
    let domain_valid = if query.domain_valid() {
        QUERY_FLAG_DOMAIN_VALID
    } else {
        0
    };
    write_byte(body, flags, domain_valid)
}

fn decode_query(body: &[u8], start: usize) -> Result<UtxoQuery, InnerCodecError> {
    let key = read_array::<ADDRESS_KEY_BYTES>(body, start)?;
    let minimum_height = offset(start, ADDRESS_KEY_BYTES)?;
    let minimum_height = u32::from_be_bytes(read_array(body, minimum_height)?);
    let flags = offset(start, ADDRESS_KEY_BYTES + U32_BYTES)?;
    let flags = read_byte(body, flags)?;
    if flags & !QUERY_FLAG_DOMAIN_VALID != 0 {
        return Err(InnerCodecError::InvalidFlags);
    }
    if flags & QUERY_FLAG_DOMAIN_VALID != 0 {
        Ok(UtxoQuery::new(AddressKey::new(key), minimum_height))
    } else if all_zero(&key) {
        Ok(UtxoQuery::from_untrusted_address_key(&[], minimum_height))
    } else {
        Err(InnerCodecError::NoncanonicalInvalidDomain)
    }
}

fn encode_optional_token(
    body: &mut [u8],
    flags_start: usize,
    token_start: usize,
    presence_flag: u8,
    token: Option<&ContinuationToken>,
) -> Result<(), InnerCodecError> {
    match token {
        Some(token) => {
            write_byte(body, flags_start, presence_flag)?;
            write_array(body, token_start, token.opaque_bytes())
        }
        None => {
            write_byte(body, flags_start, 0)?;
            write_array(body, token_start, &[0; CONTINUATION_TOKEN_BYTES])
        }
    }
}

fn decode_optional_token(
    body: &[u8],
    flags_start: usize,
    token_start: usize,
    presence_flag: u8,
) -> Result<Option<ContinuationToken>, InnerCodecError> {
    let flags = read_byte(body, flags_start)?;
    if flags & !presence_flag != 0 {
        return Err(InnerCodecError::InvalidFlags);
    }
    let token = read_array::<CONTINUATION_TOKEN_BYTES>(body, token_start)?;
    if flags & presence_flag == 0 {
        if !all_zero(&token) {
            return Err(InnerCodecError::NoncanonicalAbsentToken);
        }
        Ok(None)
    } else {
        Ok(Some(ContinuationToken::from_opaque_bytes(token)))
    }
}

fn encode_result_slots<const N: usize>(
    body: &mut [u8],
    start: usize,
    slots: &[crate::records::UtxoResultSlot; N],
) -> Result<(), InnerCodecError> {
    let mut offset = start;
    for slot in slots {
        write_byte(body, offset, u8::from(slot.is_occupied()))?;
        offset = self::offset(offset, 1)?;
        if slot.is_occupied() {
            encode_utxo(body, offset, slot.padded_utxo())?;
        } else {
            write_array(body, offset, &[0; UTXO_BYTES])?;
        }
        offset = self::offset(offset, UTXO_BYTES)?;
    }
    Ok(())
}

fn decode_result_page<const N: usize>(
    body: &[u8],
    start: usize,
    outcome: QueryOutcome,
) -> Result<UtxoResultPage<N>, InnerCodecError> {
    let mut page = UtxoResultPage::empty();
    page.set_outcome(outcome);
    let mut offset = start;
    let mut saw_dummy = false;
    for index in 0..N {
        let occupied = read_byte(body, offset)?;
        offset = self::offset(offset, 1)?;
        match occupied {
            0 => {
                saw_dummy = true;
                let dummy = read_array::<UTXO_BYTES>(body, offset)?;
                if !all_zero(&dummy) {
                    return Err(InnerCodecError::NoncanonicalDummySlot);
                }
            }
            1 => {
                if saw_dummy {
                    return Err(InnerCodecError::NoncanonicalSlotOrder);
                }
                page.set_slot(index, decode_utxo(body, offset)?);
            }
            _ => return Err(InnerCodecError::InvalidOccupancy),
        }
        offset = self::offset(offset, UTXO_BYTES)?;
    }
    Ok(page)
}

fn encode_utxo(
    body: &mut [u8],
    start: usize,
    utxo: &TransparentUtxo,
) -> Result<(), InnerCodecError> {
    write_array(body, start, utxo.txid())?;
    let output_index = offset(start, TXID_BYTES)?;
    write_array(body, output_index, &utxo.output_index().to_be_bytes())?;
    let value = offset(output_index, U32_BYTES)?;
    write_array(body, value, &utxo.value_zat().to_be_bytes())?;
    let height = offset(value, U64_BYTES)?;
    write_array(body, height, &utxo.height().to_be_bytes())?;
    let script_length_start = offset(height, U32_BYTES)?;
    let script_length =
        u8::try_from(utxo.script_len()).map_err(|_| InnerCodecError::InvalidUtxoRecord)?;
    write_byte(body, script_length_start, script_length)?;
    let script = offset(script_length_start, 1)?;
    write_array(body, script, utxo.padded_script())
}

fn decode_utxo(body: &[u8], start: usize) -> Result<TransparentUtxo, InnerCodecError> {
    let txid = read_array(body, start)?;
    let output_index = offset(start, TXID_BYTES)?;
    let value = offset(output_index, U32_BYTES)?;
    let height = offset(value, U64_BYTES)?;
    let script_length_start = offset(height, U32_BYTES)?;
    let script_length = usize::from(read_byte(body, script_length_start)?);
    if script_length > TRANSPARENT_SCRIPT_CAPACITY {
        return Err(InnerCodecError::InvalidUtxoRecord);
    }
    let script = offset(script_length_start, 1)?;
    let padded_script = read_array::<TRANSPARENT_SCRIPT_CAPACITY>(body, script)?;
    if padded_script[script_length..].iter().any(|byte| *byte != 0) {
        return Err(InnerCodecError::NoncanonicalScriptPadding);
    }
    TransparentUtxo::new(
        txid,
        u32::from_be_bytes(read_array(body, output_index)?),
        u64::from_be_bytes(read_array(body, value)?),
        u32::from_be_bytes(read_array(body, height)?),
        &padded_script[..script_length],
    )
    .map_err(|_| InnerCodecError::InvalidUtxoRecord)
}

fn validate_response_shape<const N: usize>(
    page: &UtxoResultPage<N>,
    has_more: bool,
    continuation: Option<&ContinuationToken>,
) -> Result<(), InnerCodecError> {
    if !slots_are_compact(page) {
        return Err(InnerCodecError::NoncanonicalSlotOrder);
    }
    match page.outcome() {
        QueryOutcome::ResultBudgetExceeded => {
            if !has_more
                || continuation.is_none()
                || page.slots().iter().any(|slot| !slot.is_occupied())
            {
                return Err(InnerCodecError::InvalidResponseShape);
            }
        }
        QueryOutcome::Complete => {
            if has_more || continuation.is_some() {
                return Err(InnerCodecError::InvalidResponseShape);
            }
        }
        QueryOutcome::InvalidDomain
        | QueryOutcome::StoreFailure
        | QueryOutcome::ProjectionNotReady
        | QueryOutcome::InvalidContinuation => {
            if has_more || continuation.is_some() || !page.is_all_dummy() {
                return Err(InnerCodecError::InvalidResponseShape);
            }
        }
        _ => return Err(InnerCodecError::InvalidResponseShape),
    }
    Ok(())
}

fn slots_are_compact<const N: usize>(page: &UtxoResultPage<N>) -> bool {
    let mut saw_dummy = false;
    for slot in page.slots() {
        if slot.is_occupied() {
            if saw_dummy {
                return false;
            }
        } else {
            saw_dummy = true;
        }
    }
    true
}

const fn outcome_tag(outcome: QueryOutcome) -> u8 {
    match outcome {
        QueryOutcome::Complete => 0,
        QueryOutcome::ResultBudgetExceeded => 1,
        QueryOutcome::InvalidDomain => 2,
        QueryOutcome::StoreFailure => 3,
        QueryOutcome::ProjectionNotReady => 4,
        QueryOutcome::InvalidContinuation => 5,
        _ => panic!("query outcome is always one of the six defined tags"),
    }
}

const fn outcome_from_tag(tag: u8) -> Result<QueryOutcome, InnerCodecError> {
    match tag {
        0 => Ok(QueryOutcome::Complete),
        1 => Ok(QueryOutcome::ResultBudgetExceeded),
        2 => Ok(QueryOutcome::InvalidDomain),
        3 => Ok(QueryOutcome::StoreFailure),
        4 => Ok(QueryOutcome::ProjectionNotReady),
        5 => Ok(QueryOutcome::InvalidContinuation),
        _ => Err(InnerCodecError::UnknownOutcome),
    }
}

fn validate_binding(
    body: &[u8],
    start: usize,
    expected: &[u8; SESSION_BINDING_BYTES],
) -> Result<(), InnerCodecError> {
    if read_array::<SESSION_BINDING_BYTES>(body, start)? != *expected {
        return Err(InnerCodecError::SessionBindingMismatch);
    }
    Ok(())
}

fn ensure_zero(body: &[u8], start: usize) -> Result<(), InnerCodecError> {
    let reserved = body.get(start..).ok_or(InnerCodecError::LayoutInvariant)?;
    if reserved.iter().any(|byte| *byte != 0) {
        return Err(InnerCodecError::NonzeroReserved);
    }
    Ok(())
}

fn write_byte(body: &mut [u8], index: usize, value: u8) -> Result<(), InnerCodecError> {
    let destination = body
        .get_mut(index)
        .ok_or(InnerCodecError::LayoutInvariant)?;
    *destination = value;
    Ok(())
}

fn read_byte(body: &[u8], index: usize) -> Result<u8, InnerCodecError> {
    body.get(index)
        .copied()
        .ok_or(InnerCodecError::LayoutInvariant)
}

fn write_array<const N: usize>(
    body: &mut [u8],
    start: usize,
    value: &[u8; N],
) -> Result<(), InnerCodecError> {
    let end = offset(start, N)?;
    let destination = body
        .get_mut(start..end)
        .ok_or(InnerCodecError::LayoutInvariant)?;
    destination.copy_from_slice(value);
    Ok(())
}

fn read_array<const N: usize>(body: &[u8], start: usize) -> Result<[u8; N], InnerCodecError> {
    let end = offset(start, N)?;
    let source = body
        .get(start..end)
        .ok_or(InnerCodecError::LayoutInvariant)?;
    source
        .try_into()
        .map_err(|_| InnerCodecError::LayoutInvariant)
}

fn offset(start: usize, width: usize) -> Result<usize, InnerCodecError> {
    start
        .checked_add(width)
        .ok_or(InnerCodecError::LayoutOverflow)
}

/// A protected inner envelope failed shape or canonical validation.
///
/// These detailed variants are module-internal diagnostics only. The private
/// runtime adapter maps every variant through
/// [`InnerCodecError::into_uniform_external_failure`] before recording
/// outcome-labelled telemetry or producing a caller-visible failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InnerCodecError {
    ZeroSessionBinding,
    EnvelopeCapacityTooSmall { required: usize, available: usize },
    LayoutOverflow,
    LayoutInvariant,
    AuthenticationFailed,
    ProtectionUnavailable,
    VersionMismatch,
    DirectionMismatch,
    ProfileMismatch,
    SessionBindingMismatch,
    UnknownNetwork,
    UnknownOutcome,
    InvalidFlags,
    NoncanonicalInvalidDomain,
    NoncanonicalAbsentToken,
    InvalidOccupancy,
    NoncanonicalDummySlot,
    NoncanonicalSlotOrder,
    NoncanonicalScriptPadding,
    InvalidUtxoRecord,
    InvalidResponseShape,
    NonzeroReserved,
}

impl InnerCodecError {
    const fn into_uniform_external_failure(self) -> UniformExternalFailure {
        UniformExternalFailure
    }
}

/// The sole caller-visible failure class permitted for inner-codec rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UniformExternalFailure;

impl fmt::Display for UniformExternalFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("private query failed")
    }
}

impl std::error::Error for UniformExternalFailure {}

impl fmt::Display for InnerCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroSessionBinding => f.write_str("private session binding is zero"),
            Self::EnvelopeCapacityTooSmall {
                required,
                available,
            } => write!(
                f,
                "fixed envelope requires at least {required} bytes for this compiled shape; received {available}"
            ),
            Self::LayoutOverflow => f.write_str("private envelope layout arithmetic overflowed"),
            Self::LayoutInvariant => f.write_str("private envelope layout is inconsistent"),
            Self::AuthenticationFailed => {
                f.write_str("private envelope authentication failed")
            }
            Self::ProtectionUnavailable => {
                f.write_str("private envelope protection is unavailable")
            }
            Self::VersionMismatch => f.write_str("private envelope version does not match"),
            Self::DirectionMismatch => f.write_str("private envelope direction does not match"),
            Self::ProfileMismatch => f.write_str("private envelope profile does not match"),
            Self::SessionBindingMismatch => {
                f.write_str("private envelope session binding does not match")
            }
            Self::UnknownNetwork => f.write_str("private envelope network tag is invalid"),
            Self::UnknownOutcome => f.write_str("private response outcome is invalid"),
            Self::InvalidFlags => f.write_str("private envelope flags are invalid"),
            Self::NoncanonicalInvalidDomain => {
                f.write_str("private invalid-domain query is not canonical")
            }
            Self::NoncanonicalAbsentToken => {
                f.write_str("private absent continuation token is not canonical")
            }
            Self::InvalidOccupancy => f.write_str("private result occupancy tag is invalid"),
            Self::NoncanonicalDummySlot => {
                f.write_str("private dummy result slot is not canonical")
            }
            Self::NoncanonicalSlotOrder => {
                f.write_str("private result slot order is not canonical")
            }
            Self::NoncanonicalScriptPadding => {
                f.write_str("private result script padding is not canonical")
            }
            Self::InvalidUtxoRecord => f.write_str("private result record is invalid"),
            Self::InvalidResponseShape => f.write_str("private response shape is invalid"),
            Self::NonzeroReserved => f.write_str("private reserved bytes are not zero"),
        }
    }
}

impl std::error::Error for InnerCodecError {}

#[cfg(test)]
mod tests {
    use blake2::{Blake2s256, Digest};

    use super::*;
    use crate::{
        profile::{test_profile_without_recent_snapshot, PrivacyProfile},
        records::UtxoResultPage,
    };

    const RESPONSE_SLOTS: usize = 2;
    const ENVELOPE_BYTES: usize = 512;
    const SESSION_BINDING: [u8; SESSION_BINDING_BYTES] = [0x22; SESSION_BINDING_BYTES];
    const REQUEST_NONCE: [u8; ENVELOPE_NONCE_BYTES] = [0x33; ENVELOPE_NONCE_BYTES];
    const RESPONSE_NONCE: [u8; ENVELOPE_NONCE_BYTES] = [0x44; ENVELOPE_NONCE_BYTES];
    const BLOCK_HASH_DISPLAY: [u8; BLOCK_HASH_BYTES] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
        0x3e, 0x3f,
    ];
    const FIRST_TXID: [u8; TXID_BYTES] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];

    type TestCodec = PrivateQueryCodec<RESPONSE_SLOTS, ENVELOPE_BYTES>;

    struct DeterministicTestProtector {
        key: [u8; ENVELOPE_AUTHENTICATION_BYTES],
    }

    impl DeterministicTestProtector {
        const fn new() -> Self {
            Self {
                key: [0x6b; ENVELOPE_AUTHENTICATION_BYTES],
            }
        }

        fn authentication(
            &self,
            context: &EnvelopeProtectionContext,
            nonce: &[u8; ENVELOPE_NONCE_BYTES],
            body: &[u8],
        ) -> [u8; ENVELOPE_AUTHENTICATION_BYTES] {
            let mut authentication = self.key;
            let format_version = context.format_version.to_be_bytes();
            let direction = [context.direction.tag()];
            for (index, byte) in format_version
                .iter()
                .chain(direction.iter())
                .chain(context.profile_id.iter())
                .chain(context.session_binding.iter())
                .chain(nonce)
                .chain(body)
                .enumerate()
            {
                let slot = index % ENVELOPE_AUTHENTICATION_BYTES;
                authentication[slot] = authentication[slot]
                    .rotate_left((index % u8::BITS as usize) as u32)
                    ^ byte
                    ^ (index as u8).wrapping_mul(29);
            }
            authentication
        }
    }

    impl EnvelopeProtector for DeterministicTestProtector {
        fn seal(
            &self,
            context: &EnvelopeProtectionContext,
            nonce: &[u8; ENVELOPE_NONCE_BYTES],
            body: &mut [u8],
        ) -> Result<[u8; ENVELOPE_AUTHENTICATION_BYTES], ProtectionUnavailable> {
            Ok(self.authentication(context, nonce, body))
        }

        fn open(
            &self,
            context: &EnvelopeProtectionContext,
            nonce: &[u8; ENVELOPE_NONCE_BYTES],
            body: &mut [u8],
            authentication: &[u8; ENVELOPE_AUTHENTICATION_BYTES],
        ) -> Result<AuthenticationDecision, ProtectionUnavailable> {
            let expected = self.authentication(context, nonce, body);
            let accepted = expected
                .iter()
                .zip(authentication)
                .fold(0_u8, |difference, (left, right)| {
                    difference | (left ^ right)
                })
                == 0;
            Ok(if accepted {
                AuthenticationDecision::Accepted
            } else {
                AuthenticationDecision::Rejected
            })
        }
    }

    struct UnavailableTestProtector;

    impl EnvelopeProtector for UnavailableTestProtector {
        fn seal(
            &self,
            _context: &EnvelopeProtectionContext,
            _nonce: &[u8; ENVELOPE_NONCE_BYTES],
            _body: &mut [u8],
        ) -> Result<[u8; ENVELOPE_AUTHENTICATION_BYTES], ProtectionUnavailable> {
            Err(ProtectionUnavailable)
        }

        fn open(
            &self,
            _context: &EnvelopeProtectionContext,
            _nonce: &[u8; ENVELOPE_NONCE_BYTES],
            _body: &mut [u8],
            _authentication: &[u8; ENVELOPE_AUTHENTICATION_BYTES],
        ) -> Result<AuthenticationDecision, ProtectionUnavailable> {
            Err(ProtectionUnavailable)
        }
    }

    fn profile<const SLOTS: usize, const BYTES: usize>() -> PrivacyProfile {
        test_profile_without_recent_snapshot("codec-test-v1", 4, SLOTS, BYTES, 2, 60)
            .expect("test profile inputs are nonzero")
    }

    fn shape<const SLOTS: usize, const BYTES: usize>() -> CompiledQueryShape<SLOTS, BYTES> {
        CompiledQueryShape::new(profile::<SLOTS, BYTES>())
            .expect("test profile matches its compiled shape")
    }

    fn codec() -> TestCodec {
        codec_with_budget_and_session(4, 2, SESSION_BINDING)
    }

    fn codec_with_budget_and_session(
        store_reads: usize,
        cover_rounds: usize,
        session_binding: [u8; SESSION_BINDING_BYTES],
    ) -> TestCodec {
        let profile = test_profile_without_recent_snapshot(
            "codec-test-v1",
            store_reads,
            RESPONSE_SLOTS,
            ENVELOPE_BYTES,
            cover_rounds,
            60,
        )
        .expect("alternate test profile inputs are nonzero");
        let shape = CompiledQueryShape::new(profile)
            .expect("alternate test profile matches its compiled shape");
        TestCodec::new(&shape, session_binding)
            .expect("512-byte test envelope fits two fixed result slots")
    }

    fn protector() -> DeterministicTestProtector {
        DeterministicTestProtector::new()
    }

    fn checkpoint() -> PrivateQueryCheckpoint {
        checkpoint_for(PrivateNetwork::Mainnet)
    }

    fn checkpoint_for(network: PrivateNetwork) -> PrivateQueryCheckpoint {
        PrivateQueryCheckpoint::new(
            network,
            0x0102_0304,
            BLOCK_HASH_DISPLAY,
            7,
            0x0809_0a0b_0c0d_0e0f,
            0x1011_1213_1415_1617,
        )
    }

    fn query() -> UtxoQuery {
        UtxoQuery::new(AddressKey::new([0x66; ADDRESS_KEY_BYTES]), 0x1819_1a1b)
    }

    fn token() -> ContinuationToken {
        ContinuationToken::from_opaque_bytes([0x77; CONTINUATION_TOKEN_BYTES])
    }

    fn request() -> PrivateQueryRequest {
        PrivateQueryRequest::new(checkpoint(), query(), Some(token()))
    }

    fn utxo(byte: u8, height: u32) -> TransparentUtxo {
        let txid = std::array::from_fn(|index| {
            byte.wrapping_add(u8::try_from(index).expect("32-byte txid index fits u8"))
        });
        TransparentUtxo::new(
            txid,
            u32::from(byte),
            u64::from(byte) * 100,
            height,
            &[0x51; 25],
        )
        .expect("test script fits the fixed record")
    }

    fn complete_page() -> UtxoResultPage<RESPONSE_SLOTS> {
        let mut page = UtxoResultPage::empty();
        page.set_slot(0, utxo(1, 10));
        page.set_slot(1, utxo(2, 11));
        page
    }

    fn response() -> PrivateQueryResponse<RESPONSE_SLOTS> {
        PrivateQueryResponse::new(checkpoint(), complete_page(), false, None)
            .expect("complete test response is canonical")
    }

    fn digest<const N: usize>(envelope: &FixedEnvelope<N>) -> [u8; 32] {
        let mut hasher = Blake2s256::new();
        Digest::update(&mut hasher, envelope.as_bytes());
        Digest::finalize(hasher).into()
    }

    fn reseal<const N: usize>(
        envelope: FixedEnvelope<N>,
        direction: EnvelopeDirection,
        mutate: impl FnOnce(&mut [u8]),
    ) -> Result<FixedEnvelope<N>, InnerCodecError> {
        let mut bytes = *envelope.as_bytes();
        let (nonce, body, authentication) = split_envelope_mut(&mut bytes)?;
        mutate(body);
        *authentication = protector()
            .seal(&codec().protection_context(direction), nonce, body)
            .map_err(|_| InnerCodecError::ProtectionUnavailable)?;
        Ok(FixedEnvelope::from_array(bytes))
    }

    #[test]
    fn request_round_trip_has_exact_shape_and_golden_digest() -> Result<(), InnerCodecError> {
        let codec = codec();
        let request = request();
        let envelope = codec.encode_request(&request, REQUEST_NONCE, &protector())?;
        assert_eq!(envelope.as_bytes().len(), ENVELOPE_BYTES);
        assert_eq!(codec.decode_request(&envelope, &protector())?, request);
        assert_eq!(
            digest(&envelope),
            [
                243, 46, 130, 99, 165, 69, 13, 41, 40, 29, 36, 43, 205, 154, 18, 53, 68, 47, 238,
                84, 46, 168, 177, 140, 156, 222, 9, 94, 193, 53, 204, 33,
            ]
        );
        Ok(())
    }

    #[test]
    fn unavailable_protection_returns_no_output_and_preserves_input() -> Result<(), InnerCodecError>
    {
        let codec = codec();
        let unavailable = UnavailableTestProtector;
        assert!(matches!(
            codec.encode_request(&request(), REQUEST_NONCE, &unavailable),
            Err(InnerCodecError::ProtectionUnavailable)
        ));
        assert!(matches!(
            codec.encode_response(&response(), RESPONSE_NONCE, &unavailable),
            Err(InnerCodecError::ProtectionUnavailable)
        ));

        let request_envelope = codec.encode_request(&request(), REQUEST_NONCE, &protector())?;
        let request_bytes = *request_envelope.as_bytes();
        assert!(matches!(
            codec.decode_request(&request_envelope, &unavailable),
            Err(InnerCodecError::ProtectionUnavailable)
        ));
        assert_eq!(request_envelope.as_bytes(), &request_bytes);

        let response_envelope = codec.encode_response(&response(), RESPONSE_NONCE, &protector())?;
        let response_bytes = *response_envelope.as_bytes();
        assert!(matches!(
            codec.decode_response(&response_envelope, &unavailable),
            Err(InnerCodecError::ProtectionUnavailable)
        ));
        assert_eq!(response_envelope.as_bytes(), &response_bytes);
        assert_eq!(
            InnerCodecError::ProtectionUnavailable
                .into_uniform_external_failure()
                .to_string(),
            "private query failed"
        );
        Ok(())
    }

    #[test]
    fn request_layout_pins_big_endian_fields_and_reserved_tail() -> Result<(), InnerCodecError> {
        let codec = codec();
        let envelope = codec.encode_request(&request(), REQUEST_NONCE, &protector())?;
        let bytes = envelope.as_bytes();
        assert_eq!(&bytes[..ENVELOPE_NONCE_BYTES], &REQUEST_NONCE);
        let body = &bytes[ENVELOPE_NONCE_BYTES..ENVELOPE_BYTES - ENVELOPE_AUTHENTICATION_BYTES];
        assert_eq!(
            &body[VERSION_START..DIRECTION_START],
            &FORMAT_VERSION.to_be_bytes()
        );
        assert_eq!(body[DIRECTION_START], EnvelopeDirection::Request.tag());
        assert_eq!(
            &body[PROFILE_ID_START..PROFILE_ID_START + PROFILE_ID_BYTES],
            &codec.profile_id
        );
        assert_eq!(body[CHECKPOINT_START], PrivateNetwork::Mainnet.tag());
        assert_eq!(
            &body[CHECKPOINT_START + 1..CHECKPOINT_START + 1 + U32_BYTES],
            &0x0102_0304_u32.to_be_bytes()
        );
        assert_eq!(
            &body[CHECKPOINT_START + 1 + U32_BYTES
                ..CHECKPOINT_START + 1 + U32_BYTES + BLOCK_HASH_BYTES],
            &BLOCK_HASH_DISPLAY
        );
        assert_eq!(
            &body[REQUEST_QUERY_START..REQUEST_QUERY_START + ADDRESS_KEY_BYTES],
            &[0x66; ADDRESS_KEY_BYTES]
        );
        assert_eq!(
            &body[REQUEST_QUERY_START + ADDRESS_KEY_BYTES
                ..REQUEST_QUERY_START + ADDRESS_KEY_BYTES + U32_BYTES],
            &0x1819_1a1b_u32.to_be_bytes()
        );
        assert_eq!(
            body[REQUEST_QUERY_START + ADDRESS_KEY_BYTES + U32_BYTES],
            QUERY_FLAG_DOMAIN_VALID
        );
        assert_eq!(body[REQUEST_FLAGS_START], REQUEST_FLAG_CONTINUATION);
        assert_eq!(
            &body[REQUEST_TOKEN_START..REQUEST_TOKEN_START + CONTINUATION_TOKEN_BYTES],
            &[0x77; CONTINUATION_TOKEN_BYTES]
        );
        assert_eq!(
            &body[REQUEST_SESSION_BINDING_START
                ..REQUEST_SESSION_BINDING_START + SESSION_BINDING_BYTES],
            &SESSION_BINDING
        );
        assert!(body[REQUEST_BODY_BYTES..].iter().all(|byte| *byte == 0));
        Ok(())
    }

    #[test]
    fn every_checkpoint_network_tag_round_trips() -> Result<(), InnerCodecError> {
        let codec = codec();
        for network in [
            PrivateNetwork::Mainnet,
            PrivateNetwork::Testnet,
            PrivateNetwork::Regtest,
        ] {
            let request = PrivateQueryRequest::new(checkpoint_for(network), query(), None);
            let envelope = codec.encode_request(
                &request,
                [network.tag() + 1; ENVELOPE_NONCE_BYTES],
                &protector(),
            )?;
            assert_eq!(codec.decode_request(&envelope, &protector())?, request);
        }
        Ok(())
    }

    #[test]
    fn response_round_trip_has_exact_shape_and_golden_digest() -> Result<(), InnerCodecError> {
        let codec = codec();
        let response = response();
        let envelope = codec.encode_response(&response, RESPONSE_NONCE, &protector())?;
        assert_eq!(envelope.as_bytes().len(), ENVELOPE_BYTES);
        assert_eq!(codec.decode_response(&envelope, &protector())?, response);
        assert_eq!(
            digest(&envelope),
            [
                140, 143, 245, 55, 145, 47, 35, 181, 122, 31, 132, 46, 182, 64, 252, 110, 207, 29,
                112, 253, 15, 193, 124, 118, 31, 85, 167, 49, 138, 55, 37, 107,
            ]
        );
        Ok(())
    }

    #[test]
    fn response_layout_pins_slots_flags_and_reserved_tail() -> Result<(), InnerCodecError> {
        let codec = codec();
        let envelope = codec.encode_response(&response(), RESPONSE_NONCE, &protector())?;
        let bytes = envelope.as_bytes();
        let body = &bytes[ENVELOPE_NONCE_BYTES..ENVELOPE_BYTES - ENVELOPE_AUTHENTICATION_BYTES];
        let layout = response_layout(RESPONSE_SLOTS)?;
        assert_eq!(
            body[RESPONSE_OUTCOME_START],
            outcome_tag(QueryOutcome::Complete)
        );
        assert_eq!(body[RESPONSE_SLOTS_START], 1);
        assert_eq!(
            &body[RESPONSE_SLOTS_START + 1..RESPONSE_SLOTS_START + 1 + TXID_BYTES],
            &FIRST_TXID
        );
        assert_eq!(
            &body[RESPONSE_SLOTS_START + 1 + TXID_BYTES
                ..RESPONSE_SLOTS_START + 1 + TXID_BYTES + U32_BYTES],
            &1_u32.to_be_bytes()
        );
        assert_eq!(body[layout.flags], 0);
        assert!(body[layout.token..layout.token + CONTINUATION_TOKEN_BYTES]
            .iter()
            .all(|byte| *byte == 0));
        assert_eq!(
            &body[layout.session_binding..layout.session_binding + SESSION_BINDING_BYTES],
            &SESSION_BINDING
        );
        assert!(body[layout.body_end..].iter().all(|byte| *byte == 0));
        Ok(())
    }

    #[test]
    fn codec_rejects_impossible_profile_shapes_and_zero_binding() {
        assert!(matches!(
            PrivateQueryCodec::<2, 128>::new(&shape(), SESSION_BINDING),
            Err(InnerCodecError::EnvelopeCapacityTooSmall {
                required: 446,
                available: 128,
            })
        ));
        assert_eq!(
            TestCodec::new(&shape(), [0; SESSION_BINDING_BYTES]).err(),
            Some(InnerCodecError::ZeroSessionBinding)
        );
        assert_eq!(
            required_envelope_bytes(usize::MAX),
            Err(InnerCodecError::LayoutOverflow)
        );
    }

    #[test]
    fn request_round_trips_initial_continuation_and_invalid_domain_shapes(
    ) -> Result<(), InnerCodecError> {
        let codec = codec();
        let cases = [
            PrivateQueryRequest::new(checkpoint(), query(), None),
            request(),
            PrivateQueryRequest::new(
                checkpoint(),
                UtxoQuery::from_untrusted_address_key(&[1, 2, 3], 9),
                None,
            ),
        ];
        for (index, request) in cases.iter().enumerate() {
            let envelope = codec.encode_request(
                request,
                [u8::try_from(index + 1).expect("three test cases fit u8"); ENVELOPE_NONCE_BYTES],
                &protector(),
            )?;
            assert_eq!(
                codec.decode_request(&envelope, &protector())?,
                request.clone()
            );
        }
        Ok(())
    }

    #[test]
    fn single_bit_mutation_at_each_envelope_offset_is_rejected() -> Result<(), InnerCodecError> {
        let codec = codec();
        let request = codec.encode_request(&request(), REQUEST_NONCE, &protector())?;
        let response = codec.encode_response(&response(), RESPONSE_NONCE, &protector())?;

        for index in 0..ENVELOPE_BYTES {
            let mut tampered_request = *request.as_bytes();
            tampered_request[index] ^= 0x80;
            assert_eq!(
                codec.decode_request(&FixedEnvelope::from_array(tampered_request), &protector(),),
                Err(InnerCodecError::AuthenticationFailed),
                "request mutation at byte {index} was accepted"
            );

            let mut tampered_response = *response.as_bytes();
            tampered_response[index] ^= 0x80;
            assert_eq!(
                codec.decode_response(&FixedEnvelope::from_array(tampered_response), &protector(),),
                Err(InnerCodecError::AuthenticationFailed),
                "response mutation at byte {index} was accepted"
            );
        }
        Ok(())
    }

    #[test]
    fn direction_is_authenticated_and_encoded() -> Result<(), InnerCodecError> {
        let codec = codec();
        let request = codec.encode_request(&request(), REQUEST_NONCE, &protector())?;
        assert_eq!(
            codec.decode_response(&request, &protector()),
            Err(InnerCodecError::AuthenticationFailed)
        );

        let wrong_inner_direction = reseal(request, EnvelopeDirection::Request, |body| {
            body[DIRECTION_START] = EnvelopeDirection::Response.tag();
        })?;
        assert_eq!(
            codec.decode_request(&wrong_inner_direction, &protector()),
            Err(InnerCodecError::DirectionMismatch)
        );
        Ok(())
    }

    #[test]
    fn profile_budget_and_session_context_replays_fail_before_plaintext_decode(
    ) -> Result<(), InnerCodecError> {
        let codec = codec();
        let envelope = codec.encode_request(&request(), REQUEST_NONCE, &protector())?;

        let changed_budget = codec_with_budget_and_session(5, 2, SESSION_BINDING);
        assert_ne!(codec.profile_id, changed_budget.profile_id);
        assert_eq!(
            changed_budget.decode_request(&envelope, &protector()),
            Err(InnerCodecError::AuthenticationFailed)
        );

        let changed_session = codec_with_budget_and_session(4, 2, [0x23; SESSION_BINDING_BYTES]);
        assert_eq!(changed_session.profile_id, codec.profile_id);
        assert_eq!(
            changed_session.decode_request(&envelope, &protector()),
            Err(InnerCodecError::AuthenticationFailed)
        );
        Ok(())
    }

    #[test]
    fn authenticated_request_canonicality_rejections_are_typed() -> Result<(), InnerCodecError> {
        let codec = codec();
        let envelope = codec.encode_request(&request(), REQUEST_NONCE, &protector())?;

        let wrong_version = reseal(envelope.clone(), EnvelopeDirection::Request, |body| {
            body[VERSION_START..VERSION_START + 2].copy_from_slice(&2_u16.to_be_bytes());
        })?;
        assert_eq!(
            codec.decode_request(&wrong_version, &protector()),
            Err(InnerCodecError::VersionMismatch)
        );

        let wrong_profile = reseal(envelope.clone(), EnvelopeDirection::Request, |body| {
            body[PROFILE_ID_START] ^= 1;
        })?;
        assert_eq!(
            codec.decode_request(&wrong_profile, &protector()),
            Err(InnerCodecError::ProfileMismatch)
        );

        let wrong_binding = reseal(envelope.clone(), EnvelopeDirection::Request, |body| {
            body[REQUEST_SESSION_BINDING_START] ^= 1;
        })?;
        assert_eq!(
            codec.decode_request(&wrong_binding, &protector()),
            Err(InnerCodecError::SessionBindingMismatch)
        );

        let unknown_network = reseal(envelope.clone(), EnvelopeDirection::Request, |body| {
            body[CHECKPOINT_START] = 0xff;
        })?;
        assert_eq!(
            codec.decode_request(&unknown_network, &protector()),
            Err(InnerCodecError::UnknownNetwork)
        );

        let bad_flags = reseal(envelope.clone(), EnvelopeDirection::Request, |body| {
            body[REQUEST_FLAGS_START] |= 0x80;
        })?;
        assert_eq!(
            codec.decode_request(&bad_flags, &protector()),
            Err(InnerCodecError::InvalidFlags)
        );

        let bad_query_flags = reseal(envelope.clone(), EnvelopeDirection::Request, |body| {
            body[REQUEST_QUERY_START + ADDRESS_KEY_BYTES + U32_BYTES] |= 0x80;
        })?;
        assert_eq!(
            codec.decode_request(&bad_query_flags, &protector()),
            Err(InnerCodecError::InvalidFlags)
        );

        let nonzero_reserved = reseal(envelope, EnvelopeDirection::Request, |body| {
            body[REQUEST_BODY_BYTES] = 1;
        })?;
        assert_eq!(
            codec.decode_request(&nonzero_reserved, &protector()),
            Err(InnerCodecError::NonzeroReserved)
        );
        Ok(())
    }

    #[test]
    fn authenticated_token_presence_and_domain_encoding_are_canonical(
    ) -> Result<(), InnerCodecError> {
        let codec = codec();
        let initial = PrivateQueryRequest::new(checkpoint(), query(), None);
        let initial = codec.encode_request(&initial, REQUEST_NONCE, &protector())?;
        let absent_nonzero = reseal(initial, EnvelopeDirection::Request, |body| {
            body[REQUEST_TOKEN_START] = 1;
        })?;
        assert_eq!(
            codec.decode_request(&absent_nonzero, &protector()),
            Err(InnerCodecError::NoncanonicalAbsentToken)
        );

        let continued = codec.encode_request(&request(), REQUEST_NONCE, &protector())?;
        let present_zero = reseal(continued.clone(), EnvelopeDirection::Request, |body| {
            body[REQUEST_TOKEN_START..REQUEST_TOKEN_START + CONTINUATION_TOKEN_BYTES].fill(0);
        })?;
        let decoded = codec.decode_request(&present_zero, &protector())?;
        assert_eq!(
            decoded
                .continuation
                .as_ref()
                .expect("presence flag carries an opaque token")
                .opaque_bytes(),
            &[0; CONTINUATION_TOKEN_BYTES]
        );

        let invalid_key = reseal(continued, EnvelopeDirection::Request, |body| {
            body[REQUEST_QUERY_START + ADDRESS_KEY_BYTES + U32_BYTES] = 0;
        })?;
        assert_eq!(
            codec.decode_request(&invalid_key, &protector()),
            Err(InnerCodecError::NoncanonicalInvalidDomain)
        );
        Ok(())
    }

    #[test]
    fn response_round_trips_every_protected_outcome_shape() -> Result<(), InnerCodecError> {
        let codec = codec();
        let mut partial = UtxoResultPage::empty();
        partial.set_slot(0, utxo(1, 10));

        let mut capped = complete_page();
        capped.set_outcome(QueryOutcome::ResultBudgetExceeded);

        let cases = [
            PrivateQueryResponse::new(checkpoint(), UtxoResultPage::empty(), false, None)?,
            PrivateQueryResponse::new(checkpoint(), partial, false, None)?,
            PrivateQueryResponse::new(checkpoint(), complete_page(), false, None)?,
            PrivateQueryResponse::new(checkpoint(), capped, true, Some(token()))?,
            outcome_response(QueryOutcome::InvalidDomain)?,
            outcome_response(QueryOutcome::StoreFailure)?,
            outcome_response(QueryOutcome::ProjectionNotReady)?,
            outcome_response(QueryOutcome::InvalidContinuation)?,
        ];

        for (index, response) in cases.iter().enumerate() {
            let nonce_byte = u8::try_from(index + 1).expect("eight test cases fit u8");
            let envelope = codec.encode_response(
                response,
                [nonce_byte; ENVELOPE_NONCE_BYTES],
                &protector(),
            )?;
            assert_eq!(
                codec.decode_response(&envelope, &protector())?,
                response.clone()
            );
        }
        Ok(())
    }

    #[test]
    fn authenticated_response_rejects_malleable_slots_and_padding() -> Result<(), InnerCodecError> {
        let codec = codec();
        let response_envelope = codec.encode_response(&response(), RESPONSE_NONCE, &protector())?;

        let unknown_outcome = reseal(
            response_envelope.clone(),
            EnvelopeDirection::Response,
            |body| {
                body[RESPONSE_OUTCOME_START] = 0xff;
            },
        )?;
        assert_eq!(
            codec.decode_response(&unknown_outcome, &protector()),
            Err(InnerCodecError::UnknownOutcome)
        );

        let invalid_occupancy = reseal(
            response_envelope.clone(),
            EnvelopeDirection::Response,
            |body| {
                body[RESPONSE_SLOTS_START] = 2;
            },
        )?;
        assert_eq!(
            codec.decode_response(&invalid_occupancy, &protector()),
            Err(InnerCodecError::InvalidOccupancy)
        );

        let dummy_payload = reseal(
            response_envelope.clone(),
            EnvelopeDirection::Response,
            |body| {
                body[RESPONSE_SLOTS_START] = 0;
            },
        )?;
        assert_eq!(
            codec.decode_response(&dummy_payload, &protector()),
            Err(InnerCodecError::NoncanonicalDummySlot)
        );

        let second_slot = RESPONSE_SLOTS_START + RESULT_SLOT_BYTES;
        let gap = reseal(
            response_envelope.clone(),
            EnvelopeDirection::Response,
            |body| {
                body[RESPONSE_SLOTS_START] = 0;
                body[RESPONSE_SLOTS_START + 1..RESPONSE_SLOTS_START + RESULT_SLOT_BYTES].fill(0);
                body[second_slot] = 1;
            },
        )?;
        assert_eq!(
            codec.decode_response(&gap, &protector()),
            Err(InnerCodecError::NoncanonicalSlotOrder)
        );

        let script_start =
            RESPONSE_SLOTS_START + 1 + TXID_BYTES + U32_BYTES + U64_BYTES + U32_BYTES + 1;
        let nonzero_script_padding =
            reseal(response_envelope, EnvelopeDirection::Response, |body| {
                body[script_start + 25] = 1;
            })?;
        assert_eq!(
            codec.decode_response(&nonzero_script_padding, &protector()),
            Err(InnerCodecError::NoncanonicalScriptPadding)
        );

        let invalid_script_length = reseal(
            codec.encode_response(&response(), RESPONSE_NONCE, &protector())?,
            EnvelopeDirection::Response,
            |body| {
                body[script_start - 1] = u8::try_from(TRANSPARENT_SCRIPT_CAPACITY + 1)
                    .expect("test script capacity fits u8");
            },
        )?;
        assert_eq!(
            codec.decode_response(&invalid_script_length, &protector()),
            Err(InnerCodecError::InvalidUtxoRecord)
        );
        Ok(())
    }

    #[test]
    fn authenticated_response_flags_tokens_and_reserved_bytes_are_canonical(
    ) -> Result<(), InnerCodecError> {
        let codec = codec();
        let layout = response_layout(RESPONSE_SLOTS)?;
        let complete = codec.encode_response(&response(), RESPONSE_NONCE, &protector())?;

        let bad_flags = reseal(complete.clone(), EnvelopeDirection::Response, |body| {
            body[layout.flags] = 0x80;
        })?;
        assert_eq!(
            codec.decode_response(&bad_flags, &protector()),
            Err(InnerCodecError::InvalidFlags)
        );

        let absent_nonzero = reseal(complete.clone(), EnvelopeDirection::Response, |body| {
            body[layout.token] = 1;
        })?;
        assert_eq!(
            codec.decode_response(&absent_nonzero, &protector()),
            Err(InnerCodecError::NoncanonicalAbsentToken)
        );

        let nonzero_reserved = reseal(complete, EnvelopeDirection::Response, |body| {
            body[layout.body_end] = 1;
        })?;
        assert_eq!(
            codec.decode_response(&nonzero_reserved, &protector()),
            Err(InnerCodecError::NonzeroReserved)
        );

        let mut capped = complete_page();
        capped.set_outcome(QueryOutcome::ResultBudgetExceeded);
        let capped = PrivateQueryResponse::new(checkpoint(), capped, true, Some(token()))?;
        let capped = codec.encode_response(&capped, RESPONSE_NONCE, &protector())?;
        let present_zero = reseal(capped, EnvelopeDirection::Response, |body| {
            body[layout.token..layout.token + CONTINUATION_TOKEN_BYTES].fill(0);
        })?;
        let decoded = codec.decode_response(&present_zero, &protector())?;
        assert_eq!(
            decoded
                .continuation
                .as_ref()
                .expect("has-more flag carries an opaque token")
                .opaque_bytes(),
            &[0; CONTINUATION_TOKEN_BYTES]
        );
        Ok(())
    }

    #[test]
    fn response_constructor_rejects_outcome_token_and_page_mismatches() {
        let mut capped = complete_page();
        capped.set_outcome(QueryOutcome::ResultBudgetExceeded);
        assert_eq!(
            PrivateQueryResponse::new(checkpoint(), capped, false, None).err(),
            Some(InnerCodecError::InvalidResponseShape)
        );

        let mut invalid_with_result: UtxoResultPage<RESPONSE_SLOTS> = UtxoResultPage::empty();
        invalid_with_result.set_slot(0, utxo(1, 10));
        invalid_with_result.set_outcome(QueryOutcome::InvalidDomain);
        assert_eq!(
            PrivateQueryResponse::new(checkpoint(), invalid_with_result, false, None).err(),
            Some(InnerCodecError::InvalidResponseShape)
        );

        assert_eq!(
            PrivateQueryResponse::new(checkpoint(), complete_page(), true, Some(token())).err(),
            Some(InnerCodecError::InvalidResponseShape)
        );
    }

    #[test]
    fn debug_and_errors_do_not_expose_protected_values() {
        let request = request();
        let response = response();
        assert_eq!(
            format!("{request:?}"),
            "PrivateQueryRequest { ..REDACTED.. }"
        );
        assert_eq!(
            format!("{:?}", checkpoint()),
            "PrivateQueryCheckpoint { ..REDACTED.. }"
        );
        assert_eq!(
            format!("{response:?}"),
            "PrivateQueryResponse { slots: 2, .. }"
        );
        assert_eq!(
            InnerCodecError::AuthenticationFailed.to_string(),
            "private envelope authentication failed"
        );
        for error in [
            InnerCodecError::AuthenticationFailed,
            InnerCodecError::VersionMismatch,
            InnerCodecError::ProfileMismatch,
            InnerCodecError::SessionBindingMismatch,
            InnerCodecError::InvalidResponseShape,
        ] {
            assert_eq!(
                error.into_uniform_external_failure(),
                UniformExternalFailure
            );
            assert_eq!(
                error.into_uniform_external_failure().to_string(),
                "private query failed"
            );
        }
    }

    fn outcome_response(
        outcome: QueryOutcome,
    ) -> Result<PrivateQueryResponse<RESPONSE_SLOTS>, InnerCodecError> {
        let mut page = UtxoResultPage::empty();
        page.set_outcome(outcome);
        PrivateQueryResponse::new(checkpoint(), page, false, None)
    }
}
