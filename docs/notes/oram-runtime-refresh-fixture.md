# Live subscriber refresh fixture

The `test_dependencies` fixture starts the real persistent
`NodeBackedChainIndex` over the checked-in regtest vectors. It waits until the
subscriber publishes the source's exact tip height and hash and the matching
finalized checkpoint. Tests can then advance that linear source, wait for the
next genuine publication, and shut the indexer down before its temporary
database is removed.

The Linux `rostl-experimental` integration test uses that subscriber to refresh
`MainnetPrivateQueryRuntime` from a nonempty recent snapshot, advances one
block, rebuilds the typed finalized generation at the new seam, and refreshes
again. Linux CI must execute this test before the path is described as tested;
macOS only exercises the subscriber fixture because the typed backend fails
closed there.

This slice does not test a sealed wallet query across refresh. The production
`SessionBootstrap` omits the serving checkpoint, network, and schema material
that `PrivateQueryCodec` needs to form a request, and the only current wallet
session constructor belongs to the isolated parity harness. Publishing and
validating that client binding is a separate complete-path prerequisite. The
fixture's source is a fixed linear chain with monotonic advancement, so it also
does not provide or claim deterministic reorg coverage.
