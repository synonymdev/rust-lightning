# FFOR protocol foundation

This unpublished crate implements checked Variant D amount and anchor-channel book
calculations, signed setup and lifecycle codecs, reconnect reports, canonical books
and authenticated transcript checks from draft v0.9.4. It is shared protocol data
for the native channel engine and LDK Node. It cannot prepare an offline invoice
or receive a payment by itself. The channel engine owns live state and persistence.

Work is tracked in [ldk-node #117](https://github.com/synonymdev/ldk-node/issues/117).

## Build and portability

The runtime supports Rust 1.63 and `no_std` with `alloc`. The default `std` feature
enables Bitcoin's standard-library support and the standard error trait. The crate
contains no I/O or operating-system integration. Fixture and property-test
dependencies are checked with stable Rust separately from the runtime MSRV.

```sh
cargo check -p lightning-ffor --lib --no-default-features
# Requires stable and 1.63.0 toolchains; checks both runtime feature configurations.
lightning-ffor/ci/check-msrv.sh
```

The MSRV script creates a temporary standalone runtime build and vendors its
dependencies for Cargo 1.63. It pins compatible versions of the C build tools,
without changing the workspace lockfile. Native workspace lockfiles are ignored.

## Channel-engine baseline

The receiver port targets rust-lightning **v0.2.5**, pinned to
[`5bc1dc84b3a1b084f84de4b7ece3d978b678d894`](https://github.com/lightningdevkit/rust-lightning/commit/5bc1dc84b3a1b084f84de4b7ece3d978b678d894).
This retains the current LDK Node dependency generation and its maintenance fixes.
The Synonym fork's `main` snapshot uses `0.3.0+git` and requires a separate API
migration. It is not the baseline for this port.

## Reference and verification scope

The normative source is FFOR at
[`d719161f42d1eeb6bd6c3856d564222f03c2205e`](https://github.com/coreyphillips/ffor/tree/d719161f42d1eeb6bd6c3856d564222f03c2205e).
`tests/data/appendix-d.json` contains the public Appendix D transcript fixtures.
The extraction script reconstructs the abbreviated D.5 messages and book using the
published deterministic inputs and existing signatures, then checks the published
wire hashes and book hash before writing the fixture. No signing keys are needed.

```sh
python3 lightning-ffor/tests/data/extract_appendix_d.py /path/to/ffor/ffor-variant-d-vectors.md
cargo test -p lightning-ffor
cargo clippy -p lightning-ffor --all-targets -- -D warnings
cargo fmt -p lightning-ffor -- --check
```

Tests cover the six published transcript scenarios, including the 483-slot book,
verification of their public node signatures, both funder roles, both commitment
dust limits, an unfunded receiver, exact budgets, fee-spike reserves, negotiated
limits, deadlines, overflow and public-channel fee selection. Property tests compare
arithmetic with a wide-integer oracle and mutate budgets, amounts and transcript
domains. They do not construct or broadcast commitment transactions.

The wire parser supports `ff_init`, `ff_accept`, `ff_activate`, `ff_activate_ack`,
`ff_abort`, `ff_close` and `ff_close_ack`. It bounds message sizes and collection
counts, rejects noncanonical BigSize values, unknown mandatory TLVs and invalid
compressed points, and preserves unknown optional fields in the signed bytes.
Low-S compact signatures are verified against expected channel peer identities.
Unsigned digest construction does not require a placeholder valid signature.

`AuthenticatedSetup` derives the book exclusively from authenticated setup messages.
It checks fee bounds, unique hashes, requested hash chains, activation transcripts,
height agreement and close preimages, including prefix settlement for chained books.
It is immutable protocol data, not an epoch state machine or proof of live capacity.

`tests/data/beignet-lifecycle.json` adds five signed reference lifecycle fixtures,
including both absent and explicitly empty preimage TLVs when no payment settled.
Regenerate them with `generate_beignet_lifecycle.cjs` against the pinned Beignet
checkout, using that checkout's `ts-node/register`. Both encodings are preserved
exactly so authentication never depends on normalizing received signed bytes.

The same fixture file includes all seven reconnect states from Beignet. The
`reestablish` module reads the exact 67-byte TLV 55001 value and rejects unknown
states and nonzero Variant D sequences. It preserves the peer's reported hash as
untrusted data. The pinned Beignet sender includes its computed hash in `ACTIVATING`,
although section 11.1 specifies zeros before `ACTIVE`; local engine writers must
follow the specification. Neither form proves activation without the signed ack.

This crate originated in `ldk-node/crates/ffor-protocol` and moved into the native
workspace so the channel engine and Node share one parser and authenticated setup
implementation. The Appendix D and Beignet JSON fixtures are preserved byte for
byte. The original fixture and coverage measurements below predate that move.

The standalone [fuzz target](fuzz/README.md) exercises parsing, canonical round trips,
signatures and authenticated setup with real signed fixture seeds. A bounded local
run completed 6,359,059 inputs in 121 seconds without a crash; a run including the
reconnect parser completed 2,118,228 inputs in 31 seconds without a crash. The current
suite at that checkpoint had 66 tests and four doctests. Nightly LLVM instrumentation measured 865/892
source lines (96.97%) and 198/200 branches (99.00%) covered across this crate. Uncovered
code includes diagnostic formatting and defensive paths whose preconditions are
excluded by prior validated bounds. These are measured results, not exhaustive
proofs of correctness. After migration, the seeded fuzz target completed 2,299,173
inputs in 31 seconds without a crash.

There is no signer, persistence implementation or channel state machine in this
crate. Crash injection, monitor recovery and cross-engine regtest remain requirements
for the engine port. Passing pure protocol tests is not evidence of offline payment
settlement or recovery.

## Implementation references

The receiver and settlement port should be compared with these immutable source
revisions, in addition to the normative specification:

- [Beignet 0.21.10, `8aee31d18e596fe49a0d195b325a6e757d7a009b`](https://github.com/coreyphillips/beignet/tree/8aee31d18e596fe49a0d195b325a6e757d7a009b).
  `src/lightning/channel/channel.ts` owns voucher matching, both-view commitment
  verification, activation, freeze and drain. `src/lightning/ffor/` contains the
  wire, transcript and witness code. The Variant D setup and settlement tests
  cover acknowledgement loss, restart, rejected updates and cooperative return.
- [beignet-umbrel, `12d483462ca2eabd8ae9cc105e69affa420459f9`](https://github.com/coreyphillips/beignet-umbrel/tree/12d483462ca2eabd8ae9cc105e69affa420459f9).
  `manager/ui/src/pages/tabs/ReceiveTab.jsx` and the receive routes demonstrate
  explicit offline intent, stable request identity, existing-channel capacity
  and rejecting a response that is not explicitly offline-capable. The
  `scripts/lfbw-regtest/` FFOR scenarios exercise process-stopped receiving and
  return through the manager and daemon APIs.

These sources implement their own channel engine. They do not supply FFOR APIs
to rust-lightning or LND. Port the protocol invariants into each engine's own
commitment and persistence boundary. Do not copy deployment defaults such as
channel headroom or invoice lifetime into Bitkit as protocol guarantees. Passing
reference tests alone cannot qualify the native port.

## Trust boundaries

- Amounts, peer data and public policy are untrusted. Overflow, underpayment,
  overpayment and inconsistent budgets must fail before committing vouchers.
- Only the channel engine may supply channel type, negotiated limits, balances,
  funder identity and dust limits. Application aggregate inbound liquidity is not
  sufficient. Existing ordinary HTLCs must be drained before book validation.
- A public fee exception requires an authenticated local public channel to the
  correct receiver, all four announcement signatures, correct node/funding-key
  bindings and the onion's actual SCID. This crate only compares fee amounts.
- Hash functions operate on public transcript bytes and authenticate nothing on
  their own. Callers must validate canonical encodings and low-S signatures. The
  existing signer must retain all private keys.
- A valid book is a proposed reservation, not received money. Neither amount checks
  nor matching transcript hashes imply durable activation or invoice readiness.

There is no new unsafe code, secret storage, nonce generation or custom crypto.
SHA256 and signature verification use the existing Bitcoin dependency and its
secp256k1 implementation. No production signing API is introduced.

## Required integration

[rust-lightning #4](https://github.com/synonymdev/rust-lightning/pull/4) adds a
point-in-time verifier for actual committed vouchers and monitor claim signatures,
receiver voucher parking and signer support on the v0.2.5 baseline. This protocol
crate is a dependency of that engine, but does not itself transition live channels.
The remaining engine integration must own authenticated setup, persistent ACTIVE
freeze, activation acknowledgement replay, cooperative drain and on-chain
enforcement inside rust-lightning. A second channel state machine in
ldk-node would duplicate signing authority and is not an acceptable substitute.

After that integration, ldk-node must provide exact-amount eligibility, durable and
retry-safe preparation, invoice exposure, recovery and status through generated
Kotlin/Swift bindings. Readiness must require the agreed witness acknowledgements.
The Bitkit provider adapters must only be enabled after these real APIs exist and
the interoperability tests demonstrate payer success with the receiver stopped.

The first app profile is a positive fixed amount in whole satoshis, single-part
BOLT 11, one eligible anchor channel, with a `Receive Offline` checkbox. Amountless
invoices, just-in-time liquidity and aggregate multi-channel capacity cannot qualify.
The node must enforce the selected offline window, claim margin, chain watching and
fee funding. No production window or witness deployment is chosen by this crate.

## Receiver witness provisioning primitives

The `witness` module implements version 1/D-R manifest construction, receiver-side
decoding against `AuthenticatedSetup`, fetch-key signature authentication, and Appendix F.1
`ff_witness_provision`/`ff_witness_ack`. It reuses the authenticated canonical book and transcript
hashes. Timestamp-style voucher expiries, short retention, mismatched setup/book/activation
digests, malformed keys and noncanonical signatures are refused. There is no extension stream
in these formats: unknown versions/profiles, non-0/1 success flags and trailing bytes fail.
Refusal data is bounded opaque bytes. The 65,535-byte wire limit includes the message type.

`UnsignedManifest` supplies canonical bytes and their `ffor/witness/manifest` signing digest
to an external fetch-key signer. It exports no private key and implements no signing operation.
`PendingProvision<C>` associates exact signed manifest bytes and request ID with a caller-owned
authenticated witness connection token. `check_acknowledgement` checks the request, actual
source node and connection, claimed witness identity and retention promise before returning
an immutable `CheckedAcknowledgement<C>`. Request IDs must never be reused for different
manifests. A reconnect requires fresh request correlation with the same retained manifest.

This acknowledgement has no independent signature or H_act field on the wire. The caller must
supply transport identity from its actual handshake, persist registration keys and the exact
manifest before sending, persist the correlated acknowledgement, and bind it to the engine's
current ACTIVE epoch before any invoice use. The protocol object cannot establish those facts,
or that a witness will honor its promise. Missing/failed/short acknowledgements remain incomplete.
Receipt decryption, witness selection and invoice paths, durable receiver recovery, and a
witness service remain outside this slice.

`tests/data/beignet-witness.json` is generated from Beignet `8aee31d1` using its actual manifest
and provisioning codecs over the public Appendix D setups, with deterministic test-only fetch
key material. `generate_beignet_witness.cjs` verifies the source revision and records the
Appendix D input digest. The fixtures are new cross-implementation examples, not published
Appendix F vectors. Focused tests cover exact bytes, all truncated prefixes, signature domains,
retention/height bounds, maximum books, connection changes, retries and bounded arbitrary input.

## Witness fetch and opaque encrypted records

Appendix F.1 types 55059 and 55061 have bounded canonical codecs. `UnsignedFetch` supplies
the digest for an external fetch-key signer; `SignedFetch` verifies a compact low-S signature.
The exact signature domain is a single SHA256 of `ffor/witness/fetch`, mailbox ID, nonce and
the trailing TLV stream. Neither request ID nor wire type is signed. TLV 1 is the two-byte
pagination slot; unknown odd fields are preserved, while unknown even fields, duplicates,
nonminimal BigSize values and malformed known lengths fail. A first page with no TLVs
retains the older unpaged digest exactly. Absence and an explicit zero cursor stay distinct.

`PendingFetch<C>` retains the exact request, signed manifest and actual expected connection.
It checks the echoed request ID and authenticated transport source before checking each
record against the provisioned witness, mailbox, H_act, encryption key and canonical book
entry. `CheckedFetchPage<C>` exposes only authenticated opaque encrypted records. Its next
request must use the returned cursor and a new request ID and nonce. Slots strictly increase,
continuation must equal the final returned slot and remain below K, and traversal is capped
at K pages. Already returned pages remain available if a later page fails. The caller must
ensure mailbox-wide nonce freshness across traversals and restarts; the witness must
durably refuse reused nonces. Noise identity routes replies but never authorizes mailbox access.

Version 1 records have a 235-byte header, a compact low-S witness signature over the single
SHA256 domain `ffor/witness/record`, a 191-byte ciphertext and bounded opaque guardian
attachments. Record parsing rejects unsupported version/profile/flags, malformed points,
incorrect ciphertext hashes, invalid signatures, truncated fields and extra bytes. Guardian
attachments are outside the signature and provide no proof of payment or storage. Record
retrieval remains possible after voucher expiry and therefore has no current-height gate.

There is no Rust ECIES decryptor in this checkpoint. A witness can sign ciphertext with an
invalid AEAD tag or false plaintext; successful metadata authentication does not prove that
a payment occurred. A future decryptor must authenticate ChaCha20-Poly1305 and validate
the epoch, slot, payment hash, amount, expiry, deadline and actual preimage before crediting
or claiming a voucher. The reference uses SHA256 of the **compressed** ECDH shared point
once, then HKDF-SHA256 extract/expand with empty salt and `ffor/witness/body` as info.
The nonce is 12 zero bytes, the Poly1305 tag is appended, and AAD is the exact header with
only its final ciphertext-hash field zeroed. Applying another SHA256 to the reference
ECDH helper's output would derive the wrong key.

`generate_beignet_witness_fetch.cjs` regenerates `beignet-witness-fetch.json` from pinned
Beignet and the six public Appendix D setups. Deterministic fixture keys and ephemeral
keys are public test inputs only. The generator invokes the actual reference codecs and
encryption helper, verifies witness signatures, decrypts every generated record and checks
the published preimages. Rust tests independently compare bytes, domains, AAD and the
secp256k1 ECDH hash, but do not perform decryption. The existing witness fuzz target also
checks these new codecs and is seeded with requests, pages and signed encrypted records.

The fetch checkpoint passes 88 tests and five doctests, no_std, all-target Clippy with
warnings denied, and actual Rust 1.63 checks with and without std. The seeded witness fuzz
target completed 1,431,038 inputs in 31 seconds without a crash. These bounded checks do
not establish successful decryption, runtime storage safety or offline invoice readiness.

The requested settlement baseline is LND v0.21.3-beta. LND implementation work is
kept local. This unpublished workspace crate does not change a binding version or
a release.
