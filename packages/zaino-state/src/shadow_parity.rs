//! Feature-gated ordinary-source fixture data for cross-crate shadow tests.

use std::{collections::BTreeMap, fmt, io};

use zaino_common::network::ActivationHeights;
use zebra_chain::{parameters::NetworkKind, transparent::Address};
use zebra_rpc::client::GetAddressBalanceRequest;

use crate::{
    chain_index::{
        shadow_vectors::{
            build_active_mockchain_source, load_test_vectors, try_indexed_block_chain,
            TestVectorBlockData,
        },
        source::{mockchain_source::MockchainSource, BlockchainSource},
    },
    AddrScript, BlockHash, IndexedBlock, ScriptType, TransactionHash,
};

const ABSENT_ADDRESS_HASH: [u8; 20] = [0x5a; 20];

/// One ordinary-source UTXO normalized to Zaino's internal transaction byte order.
#[derive(Clone, PartialEq, Eq)]
pub struct OrdinaryTransparentUtxo {
    txid: [u8; 32],
    output_index: u32,
    script: Vec<u8>,
    value_zat: u64,
    height: u32,
}

impl OrdinaryTransparentUtxo {
    /// Returns the transaction identifier in Zaino's internal byte order.
    pub const fn txid(&self) -> &[u8; 32] {
        &self.txid
    }

    /// Returns the transparent output index.
    pub const fn output_index(&self) -> u32 {
        self.output_index
    }

    /// Returns the exact transparent locking script.
    pub fn script(&self) -> &[u8] {
        &self.script
    }

    /// Returns the output value in zatoshis.
    pub const fn value_zat(&self) -> u64 {
        self.value_zat
    }

    /// Returns the mined block height.
    pub const fn height(&self) -> u32 {
        self.height
    }
}

/// One deterministic address query and its ordinary-source UTXO result.
#[derive(Clone, PartialEq, Eq)]
pub struct OrdinaryUtxoShadowCase {
    name: &'static str,
    address_script: AddrScript,
    ordinary_utxos: Vec<OrdinaryTransparentUtxo>,
    must_be_empty: bool,
}

impl OrdinaryUtxoShadowCase {
    /// Returns a stable diagnostic label for this fixture case.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the exact standard address script queried by both implementations.
    pub const fn address_script(&self) -> &AddrScript {
        &self.address_script
    }

    /// Returns the ordinary source's normalized UTXOs.
    pub fn ordinary_utxos(&self) -> &[OrdinaryTransparentUtxo] {
        &self.ordinary_utxos
    }

    /// Returns whether this deterministic case is required to be empty.
    pub const fn must_be_empty(&self) -> bool {
        self.must_be_empty
    }
}

/// Indexed blocks and ordinary address results bound to one finalised checkpoint.
pub struct OrdinaryUtxoShadowFixture {
    indexed_blocks: Vec<IndexedBlock>,
    checkpoint_height: u32,
    checkpoint_hash: BlockHash,
    cases: Vec<OrdinaryUtxoShadowCase>,
}

impl OrdinaryUtxoShadowFixture {
    /// Returns the genesis-forward indexed blocks through the checkpoint.
    pub fn indexed_blocks(&self) -> &[IndexedBlock] {
        &self.indexed_blocks
    }

    /// Returns the immutable vector tip treated as finalized by this fixture.
    pub const fn checkpoint_height(&self) -> u32 {
        self.checkpoint_height
    }

    /// Returns the canonical block hash at the checkpoint.
    pub const fn checkpoint_hash(&self) -> &BlockHash {
        &self.checkpoint_hash
    }

    /// Returns every standard address observed in the prefix plus one absent case.
    pub fn cases(&self) -> &[OrdinaryUtxoShadowCase] {
        &self.cases
    }
}

/// Failed construction of the deterministic ordinary-source shadow fixture.
#[derive(Debug)]
pub enum OrdinaryUtxoShadowError {
    /// The checked-in vector files could not be read or converted.
    VectorData(io::Error),
    /// The checked-in vector chain is empty.
    EmptyVectorChain,
    /// Indexed materialization did not reach the computed public checkpoint.
    MissingCheckpoint {
        /// Fixture-finalized height absent from the materialized prefix.
        height: u32,
    },
    /// The ordinary source did not report a complete best-chain checkpoint.
    OrdinaryCheckpointUnavailable,
    /// The ordinary source checkpoint differs from the materialized prefix.
    OrdinaryCheckpointMismatch,
    /// The static vector prefix contains no standard transparent address.
    NoStandardAddressCases,
    /// A standard script could not be normalized to a Zebra address.
    StandardAddressNormalization,
    /// The ordinary source rejected a deterministic address query.
    OrdinaryQueryFailed {
        /// Stable fixture case label.
        case: &'static str,
    },
    /// The deterministic absent address unexpectedly exists in the vector chain.
    AbsentAddressCollision,
}

impl fmt::Display for OrdinaryUtxoShadowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VectorData(error) => write!(f, "shadow fixture vector data failed: {error}"),
            Self::EmptyVectorChain => f.write_str("shadow fixture vector chain is empty"),
            Self::MissingCheckpoint { height } => write!(
                f,
                "shadow fixture did not materialize checkpoint height {height}"
            ),
            Self::OrdinaryCheckpointUnavailable => {
                f.write_str("shadow fixture ordinary checkpoint is unavailable")
            }
            Self::OrdinaryCheckpointMismatch => {
                f.write_str("shadow fixture ordinary checkpoint does not match its block prefix")
            }
            Self::NoStandardAddressCases => {
                f.write_str("shadow fixture static prefix has no standard address")
            }
            Self::StandardAddressNormalization => {
                f.write_str("shadow fixture standard script could not be normalized")
            }
            Self::OrdinaryQueryFailed { case } => {
                write!(f, "ordinary-source UTXO query failed for {case} case")
            }
            Self::AbsentAddressCollision => {
                f.write_str("shadow fixture absent address unexpectedly exists in the vector chain")
            }
        }
    }
}

impl std::error::Error for OrdinaryUtxoShadowError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::VectorData(error) => Some(error),
            Self::EmptyVectorChain
            | Self::MissingCheckpoint { .. }
            | Self::OrdinaryCheckpointUnavailable
            | Self::OrdinaryCheckpointMismatch
            | Self::NoStandardAddressCases
            | Self::StandardAddressNormalization
            | Self::OrdinaryQueryFailed { .. }
            | Self::AbsentAddressCollision => None,
        }
    }
}

impl From<io::Error> for OrdinaryUtxoShadowError {
    fn from(error: io::Error) -> Self {
        Self::VectorData(error)
    }
}

/// Loads ordinary UTXO results and matching `IndexedBlock`s at the immutable
/// tip of the checked-in regtest vector chain, treated as finalized by this
/// offline fixture.
pub async fn load_ordinary_utxo_shadow_fixture(
) -> Result<OrdinaryUtxoShadowFixture, OrdinaryUtxoShadowError> {
    let vectors = load_test_vectors()?;
    let tip_height = vectors
        .blocks
        .last()
        .map(|block| block.height)
        .ok_or(OrdinaryUtxoShadowError::EmptyVectorChain)?;
    let checkpoint_height = tip_height;
    let source = build_active_mockchain_source(checkpoint_height, vectors.blocks.clone());
    let indexed_blocks = try_indexed_block_chain(&vectors.blocks)
        .take(checkpoint_height as usize + 1)
        .collect::<io::Result<Vec<_>>>()?;
    let checkpoint_hash = indexed_blocks
        .last()
        .filter(|block| u32::from(block.height()) == checkpoint_height)
        .map(|block| *block.hash())
        .ok_or(OrdinaryUtxoShadowError::MissingCheckpoint {
            height: checkpoint_height,
        })?;
    let ordinary_height = source
        .get_best_block_height()
        .await
        .map_err(|_| OrdinaryUtxoShadowError::OrdinaryCheckpointUnavailable)?
        .ok_or(OrdinaryUtxoShadowError::OrdinaryCheckpointUnavailable)?;
    let ordinary_hash = source
        .get_best_block_hash()
        .await
        .map_err(|_| OrdinaryUtxoShadowError::OrdinaryCheckpointUnavailable)?
        .ok_or(OrdinaryUtxoShadowError::OrdinaryCheckpointUnavailable)?;
    if ordinary_height.0 != checkpoint_height || BlockHash::from(ordinary_hash) != checkpoint_hash {
        return Err(OrdinaryUtxoShadowError::OrdinaryCheckpointMismatch);
    }

    let vector_prefix = vectors.blocks.get(..indexed_blocks.len()).ok_or(
        OrdinaryUtxoShadowError::MissingCheckpoint {
            height: checkpoint_height,
        },
    )?;
    let mut cases = observed_standard_cases(vector_prefix, &source).await?;
    let absent_address = Address::from_pub_key_hash(NetworkKind::Testnet, ABSENT_ADDRESS_HASH);
    let absent_script = AddrScript::new(ABSENT_ADDRESS_HASH, ScriptType::P2PKH as u8);
    if cases
        .iter()
        .any(|case| case.address_script() == &absent_script)
    {
        return Err(OrdinaryUtxoShadowError::AbsentAddressCollision);
    }
    let absent_utxos = ordinary_utxos("absent", absent_address.to_string(), &source).await?;
    if !absent_utxos.is_empty() {
        return Err(OrdinaryUtxoShadowError::AbsentAddressCollision);
    }
    cases.push(OrdinaryUtxoShadowCase {
        name: "absent",
        address_script: absent_script,
        ordinary_utxos: absent_utxos,
        must_be_empty: true,
    });

    Ok(OrdinaryUtxoShadowFixture {
        indexed_blocks,
        checkpoint_height,
        checkpoint_hash,
        cases,
    })
}

async fn observed_standard_cases(
    blocks: &[TestVectorBlockData],
    source: &MockchainSource,
) -> Result<Vec<OrdinaryUtxoShadowCase>, OrdinaryUtxoShadowError> {
    let network = ActivationHeights::default().to_regtest_network();
    let mut addresses = BTreeMap::new();
    for block in blocks {
        for transaction in &block.zebra_block.transactions {
            for output in transaction.outputs() {
                let Some(address_script) =
                    AddrScript::from_script(output.lock_script.as_raw_bytes())
                else {
                    continue;
                };
                let address = output
                    .address(&network)
                    .ok_or(OrdinaryUtxoShadowError::StandardAddressNormalization)?;
                addresses.entry(address_script).or_insert(address);
            }
        }
    }
    if addresses.is_empty() {
        return Err(OrdinaryUtxoShadowError::NoStandardAddressCases);
    }

    let mut cases = Vec::with_capacity(addresses.len());
    for (address_script, address) in addresses {
        cases.push(OrdinaryUtxoShadowCase {
            name: "observed",
            address_script,
            ordinary_utxos: ordinary_utxos("observed", address.to_string(), source).await?,
            must_be_empty: false,
        });
    }
    Ok(cases)
}

async fn ordinary_utxos(
    case: &'static str,
    address: String,
    source: &MockchainSource,
) -> Result<Vec<OrdinaryTransparentUtxo>, OrdinaryUtxoShadowError> {
    source
        .get_address_utxos(GetAddressBalanceRequest::new(vec![address]))
        .await
        .map_err(|_| OrdinaryUtxoShadowError::OrdinaryQueryFailed { case })
        .map(|utxos| {
            utxos
                .into_iter()
                .map(|utxo| {
                    let (_address, txid, output_index, script, value_zat, height) =
                        utxo.into_parts();
                    OrdinaryTransparentUtxo {
                        txid: TransactionHash::from(txid).0,
                        output_index: output_index.index(),
                        script: script.as_raw_bytes().to_vec(),
                        value_zat,
                        height: height.0,
                    }
                })
                .collect()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fixture_binds_ordinary_cases_to_the_exact_static_checkpoint(
    ) -> Result<(), OrdinaryUtxoShadowError> {
        let fixture = load_ordinary_utxo_shadow_fixture().await?;

        assert_eq!(fixture.checkpoint_height(), 200);
        assert_eq!(fixture.indexed_blocks().len(), 201);
        assert_eq!(
            fixture.indexed_blocks().last().map(IndexedBlock::hash),
            Some(fixture.checkpoint_hash())
        );
        assert!(fixture.cases().len() > 1);
        assert!(fixture
            .cases()
            .iter()
            .filter(|case| !case.must_be_empty())
            .any(|case| !case.ordinary_utxos().is_empty()));
        assert!(fixture
            .cases()
            .iter()
            .find(|case| case.must_be_empty())
            .is_some_and(|case| case.ordinary_utxos().is_empty()));
        assert!(fixture.cases().iter().all(|case| {
            case.ordinary_utxos().iter().all(|utxo| {
                utxo.height() <= fixture.checkpoint_height() && !utxo.script().is_empty()
            })
        }));
        Ok(())
    }
}
