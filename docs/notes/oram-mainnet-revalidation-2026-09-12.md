# Recovered mainnet capture: current-reader revalidation

On 2026-09-12, the current Rust `corpus size` command accepted the recovered
three-file mainnet capture, published its sizing bundle, and completed automatic
read-back validation. A separate `corpus validate-sizing` invocation accepted
the new bundle against that capture. Both commands exited successfully.

The qualification digest exactly reproduces the historical result:

```text
measurement_blake2s256=aba46f64da0113d9b0e93209ab4a8a98626d6d5bc7973444c8bf766a1922b127
sizing_model_blake2s256=8ff797d7a57f6e07c0d4de5049178ef11568edd5c0c98e10bf30fd42ba50b58a
qualification_blake2s256=7c16856d25d363e9409a05408f6c6e4b6c668236e2851abcb1eb47763cd0b0f2
```

The source capture and its integrity checks are in the
[recovery ledger](oram-mainnet-capture-recovery.md). This rerun closes its
typed-reader/semantic revalidation gap; it does not measure physical capacity.

## Reproduction and execution identity

The reader was built locally on macOS/aarch64 with Rust 1.96.0
(`ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96`), LLVM 22.1.2, the default development
profile, locked dependencies, and `private-service` enabled. The latter reused
the local client-test build cache; no listener or private service was started.

The checkout base was `e501ab839fb91cb2ae3441f52e430b83c7c675fb`, with the
in-progress retained-client changes present. This is not a clean release build
or attested execution. Source was frozen during compilation; the tracked diff
and untracked retained-client source were preserved locally. Relevant SHA-256s:

| Input/output | SHA-256 |
| --- | --- |
| Reader binary | d09a4154dc1a4fb6b9eecee150af02e036de41649f479415fa4ff7fa2813d462 |
| Cargo.lock | 788e3f96b65f824469ba4a83378f3e025b90840870d9065bc75494ece2c4de37 |
| Unchanged corpus_artifact.rs | dce5a63438c818f4ababc58b792a424fa94860b98fe83f02aea36c708e1eb49d |
| Tracked source patch | 811dec7d09f9e9adf4b8d97ff3f0a559f90b82e87ea3447f4ebc9074ff9d4d75 |
| Untracked retained.rs | 269c00d76d50ec9d338f5001e344609234814081768906717f7bcb8e40a522fb |

The exact model command was:

```console
zainod-oram corpus size \
  --input-dir <RECOVERED_CAPTURE> --output-dir <NEW_SIZING_DIRECTORY> \
  --growth-horizon-years 0 --annual-growth-bps 0 \
  --directory-capacity 16777216 --directory-admission-limit 9193009 \
  --event-capacity 536870912 --event-admission-limit 351872272 \
  --max-events-per-address 3360022 --position-map-entry-bytes 4 \
  --backend-expansion-bps 10000 --tdx-memory-bytes 188978561024 \
  --required-headroom-bps 3000
zainod-oram corpus validate-sizing \
  --capture-dir <RECOVERED_CAPTURE> --sizing-dir <NEW_SIZING_DIRECTORY>
```

Earlier attempts stopped or exhausted local disk during compilation, before
the reader ran. They produced no sizing bundle and are not reader rejections.

## Results and retained artifacts

The public checkpoint is mainnet height `3425046`, hash
`0000000000a1014e9564513f1d5e5ddaba027c032857a236ca3178e9a8983ad4`.
The model uses 9,193,009 addresses, 351,872,272 events, a 3,360,022-event
maximum per address, and compiled directory/event record widths of 38/82 bytes.

Logical table allocation is 44,660,948,992 bytes; adding the logical position
map gives 46,875,541,504 bytes. The model reports a fit within 132,284,992,716
usable bytes after its 30% headroom allowance on 176 GiB. These are calculated
logical quantities, not observed allocator usage or RSS.

The exact three output files are retained at:

```text
gs://sovright-oram-research-evidence/sizing/mainnet/h3425046/7c16856d25d363e9409a05408f6c6e4b6c668236e2851abcb1eb47763cd0b0f2/revalidation-20260912-macos/
```

Uploads used a create-only generation precondition. Cloud listing confirmed
the three sizes; raw bucket metadata confirmed owning project `486673347298`,
uniform bucket-level access, and enforced public-access prevention.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| qualification.json | 1865 | ec7ce68ffa45abfbfabfd899a52a8fe6e8f94aed2b723e61f9b97c7f87351202 |
| qualification.txt | 1254 | 53c323bdaab5fe87bef5773ba1fd50dc2524b550a32537089db39eaf553292b0 |
| provenance.json | 560 | 551a558ac5e6523c9cc89cd82e802a13f8a432d201947467dfb56485f619d88e |

The provenance records macOS/aarch64. It is unsigned local provenance, not
evidence of execution on the historical Linux builder or a TDX machine.

## Remaining Track B gates

Growth remains zero and backend expansion remains the historical uncalibrated
1.0x factor. The artifact explicitly reports `insertion_bound=false`,
`backend_calibrated=false`, and `rss_measured=false`. The exact digest match
reproduces these limitations as well as the fit flags.

Actual backend allocation, position maps/stash/temporary peaks, insertion
failure bounds, growing-mainnet load, no-swap RSS headroom on the chosen TDX
target, and full-service cold recovery remain unqualified. This rerun does not
supersede retained negative insertion evidence or establish a private-server
readiness claim.
