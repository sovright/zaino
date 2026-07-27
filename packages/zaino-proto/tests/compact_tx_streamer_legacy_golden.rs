//! Legacy `CompactTxStreamer` schema golden.
//!
//! The private-query research fork must not change the existing lightwallet
//! contract. This test pins the semantic proto inputs and the readable RPC
//! surface recorded at `zingolabs/zaino@c94ae247` without requiring `protoc`
//! or another hashing dependency.

use zaino_proto::proto::service::compact_tx_streamer_server::SERVICE_NAME;

const SERVICE_PROTO: &str = include_str!("../lightwallet-protocol/walletrpc/service.proto");
const COMPACT_FORMATS_PROTO: &str =
    include_str!("../lightwallet-protocol/walletrpc/compact_formats.proto");

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

const BASELINE_SCHEMA_FINGERPRINT: u64 = 0xc973_f8b7_00bf_158f;
const BASELINE_SERVICE_NAME: &str = "cash.z.wallet.sdk.rpc.CompactTxStreamer";
const BASELINE_RPC_SIGNATURES: &[&str] = &[
    "rpc GetLatestBlock(ChainSpec) returns (BlockID) {}",
    "rpc GetBlock(BlockID) returns (CompactBlock) {}",
    "rpc GetBlockNullifiers(BlockID) returns (CompactBlock) {}",
    "rpc GetBlockRange(BlockRange) returns (stream CompactBlock) {}",
    "rpc GetBlockRangeNullifiers(BlockRange) returns (stream CompactBlock) {}",
    "rpc GetTransaction(TxFilter) returns (RawTransaction) {}",
    "rpc SendTransaction(RawTransaction) returns (SendResponse) {}",
    "rpc GetTaddressTxids(TransparentAddressBlockFilter) returns (stream RawTransaction) {}",
    "rpc GetTaddressTransactions(TransparentAddressBlockFilter) returns (stream RawTransaction) {}",
    "rpc GetTaddressBalance(AddressList) returns (Balance) {}",
    "rpc GetTaddressBalanceStream(stream Address) returns (Balance) {}",
    "rpc GetMempoolTx(GetMempoolTxRequest) returns (stream CompactTx) {}",
    "rpc GetMempoolStream(Empty) returns (stream RawTransaction) {}",
    "rpc GetTreeState(BlockID) returns (TreeState) {}",
    "rpc GetLatestTreeState(Empty) returns (TreeState) {}",
    "rpc GetSubtreeRoots(GetSubtreeRootsArg) returns (stream SubtreeRoot) {}",
    "rpc GetAddressUtxos(GetAddressUtxosArg) returns (GetAddressUtxosReplyList) {}",
    "rpc GetAddressUtxosStream(GetAddressUtxosArg) returns (stream GetAddressUtxosReply) {}",
    "rpc GetLightdInfo(Empty) returns (LightdInfo) {}",
    "rpc Ping(Duration) returns (PingResponse) {}",
];

fn source_before_comment(line: &str) -> &str {
    match line.split_once("//") {
        Some((source, _)) => source,
        None => line,
    }
}

fn update_fingerprint(mut fingerprint: u64, byte: u8) -> u64 {
    fingerprint ^= u64::from(byte);
    fingerprint.wrapping_mul(FNV_PRIME)
}

fn schema_fingerprint(sources: &[(&str, &str)]) -> u64 {
    let mut fingerprint = FNV_OFFSET_BASIS;
    for (name, source) in sources {
        for byte in name.bytes() {
            fingerprint = update_fingerprint(fingerprint, byte);
        }
        fingerprint = update_fingerprint(fingerprint, 0);

        for line in source.lines() {
            for byte in source_before_comment(line).bytes() {
                if !byte.is_ascii_whitespace() {
                    fingerprint = update_fingerprint(fingerprint, byte);
                }
            }
        }
        fingerprint = update_fingerprint(fingerprint, 0xff);
    }
    fingerprint
}

fn compact_tx_streamer_rpc_signatures(source: &str) -> Vec<&str> {
    let mut in_service = false;
    let mut signatures = Vec::new();

    for line in source.lines() {
        let line = source_before_comment(line).trim();
        if !in_service {
            in_service = line == "service CompactTxStreamer {";
            continue;
        }
        if line == "}" {
            break;
        }
        if line.starts_with("rpc ") {
            signatures.push(line);
        }
    }

    signatures
}

#[test]
fn legacy_compact_tx_streamer_schema_matches_c94ae247() {
    assert_eq!(SERVICE_NAME, BASELINE_SERVICE_NAME);
    assert_eq!(
        compact_tx_streamer_rpc_signatures(SERVICE_PROTO),
        BASELINE_RPC_SIGNATURES
    );
    assert_eq!(
        schema_fingerprint(&[
            ("service.proto", SERVICE_PROTO),
            ("compact_formats.proto", COMPACT_FORMATS_PROTO),
        ]),
        BASELINE_SCHEMA_FINGERPRINT,
        "legacy proto schema drifted from zingolabs/zaino@c94ae247; audit wire compatibility before updating the golden",
    );
}
