# Experimental FFOR receiver setup, parking and activation guards

This fork targets rust-lightning v0.2.5. The current APIs provide receiver voucher
parking and point-in-time verification of both commitment views for FFOR Variant D.
They do not provide an active offline receiving epoch.

`register_ffor_receiver_setup` authenticates exact signed init and accept messages
against the manager's actual node identity, chain and current height. It checks the
empty, connected, synchronized anchor channel, funding terms, commitment number,
exact next incoming HTLC ID, fees, dust and reserves before installing the book.
Admission currently refuses channels with more than 4096 revealed peer commitments
until a bounded persistent history index exists. It rejects reuse of a revealed
commitment secret, including the secret disclosed by the voucher commitment round.

The caller supplies a positive claim margin from local deployment policy. The
voucher expiry must be a block height and at least the settlement deadline plus
that margin. This does not select a production reconciliation floor or establish
watcher-free eligibility. The setup remains ineligible for offline invoices.

`register_ffor_receiver_book` is the lower-level experimental parking API. It checks
the public book's structural invariants and exact first incoming HTLC ID, but does
not retain signed setup evidence and cannot authorize later activation. Both APIs
request manager persistence without waiting for a durable write. The application
must persist registration before allowing the settlement peer to send vouchers.

Registration returns an opaque persistence requirement. The background processor
captures a token before encoding the manager and completes it only after its
ordered store reports success, both in its processing loop and during shutdown.
`is_ffor_state_persisted` remains false while the write is pending or has failed or
been cancelled. A completed older snapshot cannot release a later mutation, and
tokens from another manager instance or a restart are refused. Custom persistence
loops must follow the same capture, encode, durable write, completion sequence.
After consuming a notification, a custom loop must explicitly retry a cancelled
write by checking `get_and_clear_needs_persistence`; notifications are edge-triggered.
Storage completion alone does not prove that the channel still has the same phase.

The shared `lightning-ffor` crate owns bounded wire parsing, signature verification,
authenticated setup derivation and transcript hashes. Its runtime supports
`no_std` with `alloc` and Rust 1.63. Node consumes this same crate from the pinned
fork revision. The crate has no channel mutation or invoice authority.

The stock channel owns voucher identity through the ordinary commitment rounds.
Exact vouchers never enter invoice, keysend, or forwarding processing. The receiver
only derives encrypted failure material from their onion keys. `Registered` reports
progress; `Parked` additionally requires the complete monitor-backed commitment proof,
including both current commitment transactions and holder claim signatures.

`request_ffor_receiver_quiescence` starts an owned STFU handshake only for a
complete authenticated book and peers that support quiescence. It retains the
monitor proof and checks it again after both STFU messages, including the receiver's
initiator role and the settlement deadline. An intervening commitment or monitor
update invalidates the proof. `ffor_receiver_quiescence_status` distinguishes a
pending handshake from completed, still-valid quiescence. Neither state authorizes
an invoice. Stock quiescence ends on disconnect and is not an activation freeze.

The owned handshake excludes a competing splice. Explicit abort after sending
STFU requests a disconnect before voucher failures can drain on reconnection.
Timeout, disconnect and restart also unwind setup; force-close remains available.
Only the epoch identity is serialized in a required action variant. Transient
monitor evidence is discarded on restart, which aborts the setup. The runtime must
enforce its handshake deadline through explicit abort, alongside the existing
stock peer timeout.

An explicit abort, mismatch, disconnect, or restart unwinds committed vouchers using
ordinary HTLC failure rounds. Partial rounds finish before their HTLCs are failed.
`Aborting` and `Aborted` distinguish pending removal from a synchronized channel with
all owned HTLCs drained. Ordinary payments work after drain. Registered voucher
hashes remain excluded from ordinary receiving.

There is deliberately only one registration per channel. Its epoch and public book
remain as a permanent tombstone, and attempts to register either the same or another
epoch are refused. The required even channel TLV 65534 is retained after abort;
older readers must reject the channel. Restore validates live voucher ownership
against stock inbound HTLCs before accepting the channel, and checks that committed
vouchers retain either failure material or their deferred add.

Authenticated setup also enters a manager-owned recovery registry in required TLV
22. Its exact signed messages, canonical book and original admission context survive
explicit closure, monitor-triggered closure and disposal of a stale manager channel.
Restore reauthenticates records, checks the manager's identity and chain, and requires
every retained channel setup to match its archive entry. The registry is bounded to
64 records and 8 MiB total, with a 192 KiB setup-only record limit and a 384 KiB
activation record limit. Capacity is reserved before channel mutation. An Activating
record also reserves the maximum acknowledgement size, including framing, so other
records cannot consume its eventual Active storage. This allowance is derived again
on restore and released when the acknowledgement is retained. The setup-only archive
version retains no activation or claim authority.
Fully drained channel tombstones permit subsequent ordinary splicing while retaining
the original funding context in their archive.

Private activation records now retain the exact signed activate and acknowledgement
messages, both commitment numbers and transaction IDs, monitor update identity,
preparation height and the monitor's original sweep destination. They reauthenticate
the historical transcript and permit only the first acknowledgement to be added.
A versioned registry prevents setup-only readers from accepting activation evidence.
Every retained channel fence must match its archive phase and activation hash, even
when the live channel will be discarded as stale. Restore also requires the original
monitor and checks both commitment identities, its destination and the saved update
floor. A preimage or force-close update may advance that floor without changing the
frozen commitments. The complete monitor remains necessary for signatures and claims.

The private channel fence persists Activating or Active independently of stock STFU
flags. It blocks ordinary HTLC updates, commitment and revocation messages, fees,
splicing, cooperative close, signer retries and ordinary reconnect messages. Valid
owned preimages still enter stock monitor persistence, including delayed writes and
completion after channel removal. They cannot release an ordinary fulfill while the
fence is held. Force-close remains available. A required even field makes older
channel readers refuse fenced state. Installation currently exists only in tests;
there is no production transition into these phases or recovery driver to leave them.

These are consistency checks, not an authenticated storage envelope. Arbitrarily
deleting a mismatching add's ownership record after abort can make its nonreserved
hash indistinguishable from an ordinary post-abort payment. No valid writer creates
that state: the ownership record and stock HTLC are written together. The current
checks do not claim to detect every arbitrary alteration of local storage.
Similarly, an archive without its original live channel cannot independently prove
the historical funding context against arbitrary local storage alteration.

No feature bit, production wire activation, invoice readiness, authenticated
reconnect driver or automatic setup deadline is implemented here. The caller must abort a setup that times out.
Ordinary channel updates can invalidate a previously returned `Parked` proof.

`NodeSigner::sign_ffor_message` supplies the protocol's single-SHA256 `ffor/msg`
signature domain without exporting node keys. KeysManager uses its existing ECDSA
implementation with auxiliary entropy; phantom wallets use their actual local node
identity. External signers refuse this operation by default. Signing requests check
only the allowed envelope type and size; protocol and transition validation remain
required before requesting a signature.

## Validation

The FFOR tests exercise real two-node commitment rounds, both funding directions,
asymmetric dust limits and contest delays, signature corruption, stale monitors,
monitor persistence delays, exact and partial books, mismatching and extra adds,
and ordinary payments after abort. The parking crash matrix reloads at registration,
uncommitted add, first commitment, both commitments before interception, parked,
explicit abort, failure commitment sent, and fully drained tombstone.

Run the focused suite with:

```sh
cargo test -p lightning --lib ffor_ --offline
```

The compatibility test can export ordinary and registered channel fixtures with
`FFOR_LEGACY_FIXTURE_DIR`. An unmodified v0.2.5 channel reader accepted the ordinary
fixture and rejected the registered fixture with `UnknownRequiredFeature`.
The same unmodified release reader accepted an ordinary manager fixture and
rejected an archive-only manager fixture with `UnknownRequiredFeature`, after its
last live channel had already been removed.
Existing payment, reload, monitor, and quiescence suites also pass.
Three signer tests additionally verify the public Appendix D activation signature,
domain/type separation, local node identity, low-S output and default refusal.
The manager tests cover revision ordering, stale instances and signer retry after
restart. Background-processor tests inject delayed, failed and cancelled writes,
then verify successful retries and both synchronous and asynchronous final writes.
Authenticated setup tests cover signature and identity mismatches, funding and
commitment mismatches, history bounds, block-height expiry and revealed-secret reuse.
Registry and manager recovery tests cover closure retention, stale channel disposal,
missing or conflicting records, capacity refusal and archive-only serialization.
Quiescence tests cover real STFU exchange, unsupported peers, competing actions,
partial rounds, delayed monitors, changed commitments, deadline equality, initiator
tie loss, pending abort, disconnect, restart and force-close. The ordinary
quiescence and splice suites also pass with these channel changes.

The private fence tests cover both phases and funding directions, restored pending
state rejection, preimage retention, cleared STFU flags, signer and monitor callbacks,
reconnect refusal and force-close. Activation recovery tests use real committed
channels and signed transcripts, exercise retained evidence after closure, and reject
missing monitors, mismatched commitment identities, downgrade attempts and substituted
transcripts. Capacity tests reload a registry with competing admissions and retain a
maximum signed acknowledgement from its reserved allowance.

## Next boundary

Reusable epochs require durable retired epoch IDs and voucher hashes, with one
current signed transcript record under the same channel authority. A production
activation owner must derive and sign the exact transcript from owned quiescence,
atomically install its archive and fence, and release wire only after the manager
persistence barrier completes. Acknowledgement handling must authenticate the peer,
retain Active evidence and recheck the channel phase before reporting durability.
Reconnect needs the Variant D state comparison and acknowledgement-loss recovery;
ordinary channel traffic must remain frozen throughout. Witness/mailbox recovery,
preimage reconciliation, controlled voucher drain and invoice eligibility remain
separate required boundaries. None can be inferred from a retained setup or the
private activation fixtures.
