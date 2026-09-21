# Experimental FFOR receiver setup, activation and recovery

This fork targets rust-lightning v0.2.5. The current APIs provide receiver voucher
parking and verification of both commitment views for FFOR Variant D. Native manager
transitions compose activation, reconnect, pre-active abort and cooperative voucher drain
with ordered storage.
An experimental public receiver facade owns pre-init admission, synchronous peer input,
activation and cooperative close advancement. Production transport orchestration and
invoice readiness remain unfinished.

`prepare_ffor_receiver` checks the current authenticated native peer generation,
derives a fresh protocol epoch and signs the exact Init. Before any bytes leave,
it installs a channel-owned interception gate and reserves bounded recovery storage.
`advance_ffor_receiver` releases those bytes only after the ordered manager write
completes, the original connection remains current and the settlement deadline has
not passed. Backpressure preserves the exact retry; successful queue insertion
consumes this one-shot send. Disconnect and restart never replay Init.

After Accept, the same advancement API chooses the next action from native lifecycle
state. It requests an opaque monitor snapshot when proof is needed; callers must drop
the monitor guard before `advance_ffor_receiver_with_monitor`. Complete voucher proof
starts the owned STFU exchange, then a fresh matching snapshot permits activation
preparation. Every transition rechecks the authenticated connection generation under
its own native peer lock. Persisted exact Activate is released at most once, and an
authentic ActivateAck enters the existing persistence-gated Active transition.

`request_ffor_receiver_close` retains an exact signed close intent. Subsequent advances
release it after persistence, import acknowledged preimages before enabling failures,
drive stock removal rounds and verify the final empty commitment pair before Closed.
Restored Draining and Closed may complete their local persistence gates before stock
reestablish finishes; their outgoing reports depend on that completion. Conflicting
reports retain the fence. An exact CloseAck after a required close replay requests a
fresh reconnect so stock commitment replay can reconcile the new report.

New setup, STFU and activation releases check the current settlement deadline.
Historical signed acknowledgements and close recovery remain usable after that
deadline. An ambiguous activation is reconciled through a fresh connection, never
replayed. Progress values such as Active, Draining or Closed do not authorize invoices
or witness provisioning. Callers must continue stock peer events, commitment rounds
and monitor/manager persistence between advances.

The application's stable `local_request_id` is local correlation, not a protocol
epoch or channel authority. An exact retry returns the retained native selector;
changed channel, peer or policy is refused. A bounded historical lookup recovers
that selector after restart or live-channel removal without granting permission
to send or expose an invoice.

The peer may send ordinary voucher adds immediately after Accept.
`handle_ffor_receiver_message` therefore processes Accept synchronously under the
native peer lock before custom message handling returns. It installs exact voucher
ownership before those adds arrive. A pre-Accept add is intercepted and aborts
negotiation; it can never be relabelled by a later Accept. If a crash leaves newer
monitor state beside the durable pre-init manager, stock stale-manager recovery
can force-close without exposing an ordinary claimable or forwarded payment.

The custom handler captures `FFORPeerConnection` only after the native successful
peer-connected callback and pairs it with its own transport generation. It must not
hold a transport mutex across a manager call. The release callback runs under native
authority and may only check its paired token and insert into a bounded queue.
Malformed or contradictory setup, cancellation, disconnect and restart retain the
interception gate. Controlled release requires durable abort state and a fresh
connection, preserving the permanent request and any accepted voucher tombstones.

The lower-level `register_ffor_receiver_setup` authenticates exact signed init and accept messages
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
not retain signed setup evidence and cannot authorize later activation. Both
low-level registration APIs require an external barrier preventing peer adds until
registration is durable. The wire protocol provides no post-Accept barrier, so an
operational receiver must use the pre-init facade instead.

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
64 records and 8 MiB total, with a 192 KiB setup-only record limit and a 512 KiB
activation record limit. Capacity is reserved before channel mutation. An Activating
record reserves its maximum acknowledgement, both maximum close messages and final
completion evidence, including framing, so competing admissions cannot consume its
remaining transition storage. Each later phase retains the allowance for its remaining
transitions, recomputed on restore. Legacy registrations release that reservation
on terminal abort. Facade requests reserve the full 512 KiB record allowance before
Init and retain it after promotion into accepted setup. Pending requests and their
local retry identity use archive version 4 and required even channel fields; they
share the same global count and byte limits with accepted records.
The setup-only archive version retains no activation or claim authority.
Fully drained channel tombstones permit subsequent ordinary splicing while retaining
the original funding context in their archive.

Private activation records now retain the exact signed activate and acknowledgement
messages, both commitment numbers and transaction IDs, monitor update identity,
preparation height and the monitor's original sweep destination. They reauthenticate
the historical transcript and permit only the first acknowledgement to be added.
A versioned registry prevents setup-only readers from accepting activation evidence.
Every retained channel fence must match its archive phase and activation hash, even
when the live channel will be discarded as stale. For unresolved activation, restore also requires the original
monitor and checks both commitment identities, its destination and the saved update
floor. A preimage or force-close update may advance that floor without changing the
frozen commitments. The complete monitor remains necessary for signatures and claims.

The private channel fence persists Activating, Active, Draining, pending Closed or
a pending pre-active abort independently of stock STFU flags. Activating and Active block
ordinary HTLC updates, commitment and revocation messages, fees, splicing, cooperative
close and signer retries. Frozen
channels are also excluded from usable-channel listings and ordinary routing. Valid
owned preimages still enter stock monitor persistence, including delayed writes and
completion after channel removal. They cannot release an ordinary fulfill while the
fence is held. Force-close remains available. A required even field makes older
channel readers refuse fenced state.

The native manager derives and signs activation from the actual completed
owned STFU handshake and monitor proof. It installs the archive and fence under the
same consistency boundary, then releases the exact signed bytes at most once after
that snapshot is durable. Release rechecks the current phase, height and original
handshake. Its transport callback must atomically validate the authenticated
connection token with queue insertion, without network I/O or manager callbacks.
A signed acknowledgement advances the channel and archive together and requests a
new persistence requirement before Active can be reported. The public receiver facade
selects and invokes these transitions without granting application readiness.

The native reconnect codec carries Variant D TLV 55001 while retaining the ordinary
BOLT commitment and revocation counter checks. Activating and Active reconnect never
retransmit ordinary commitment traffic. Draining can replay only its owned removals
through the normal commitment protocol after its durable release grants permission. A receiver still Activating can recover a lost signed
acknowledgement only after the settlement peer reports Active with the same epoch and
activation hash. An unsigned report alone cannot activate the receiver. Activation
bytes are never replayed across a disconnect or restart. Active conflicts retain the
fence for future resolution or force-close.

Other pre-active reconnect outcomes create a permanent abort record and keep the
channel frozen until that record is durable. Only then can the private manager owner
release ordinary voucher drain. Known preimages remain ahead of failures, including
preimages waiting for monitor persistence. Terminal abort evidence survives drain and
later ordinary payments without requiring the original frozen commitment pair. It
permanently refuses acknowledgement replay or replacement activation.

Outgoing reconnect reports use the existing per-peer queue. A report and the queue
suffix behind it wait until the latest retained phase is durable. The FFOR report is
refreshed at release while the original ordinary reconnect counters are retained.
Restored managers request a fresh persistence requirement and notify the background
processor before releasing reports. Disconnect discards connection-specific queued
reports, and a subsequent connection builds fresh ones.

Cooperative close retains exact signed receiver intent and settlement acknowledgement,
including the settled bitmap and all acknowledged preimages. These records use archive
version 3 and a required even activation field. Exact control-message replay remains
idempotent through later phases; different bytes cannot replace retained evidence.
The private manager persists the close acknowledgement before enabling Draining.
Its native permission is instance-local and resets to false on restore. Known preimages
enter the stock monitor before any eligible voucher failures are queued. Settled slots
and slots with known preimages cannot receive new failure decisions. An unsent failure
can become a fulfill; a preimage learned after a signed failure still reaches the monitor
without rewriting an already committed removal.

Draining permits only owned voucher removals and their commitment, revocation, monitor
and signer work. Adds, fees, STFU, splicing and ordinary cooperative close remain blocked.
A matching peer Draining or Closed report uses normal BOLT replay once permission is
released. A matching Active report enters control-message-only recovery for exact
retained close retransmission. After its signed reply the facade requests a reconnect
to rebuild ordinary replay obligations; same-connection drain stays disabled. Conflicting
reports retain the fence for resolution. Outgoing Draining reports otherwise remain
queued until native drain permission is enabled, even when the archive write is complete.

Closed requires a fresh proof that both actual commitment transactions have no HTLCs,
all removal rounds and monitor writes completed, and funding and claim signatures match.
The archived completion binds the funding outpoint, both transaction IDs and commitment
numbers, acknowledgement, activation and monitor update identity. The final write must
complete before the manager clears the fence or advertises Closed. Ordinary payments
and later splices then work while the permanent epoch and voucher tombstone remains.

Witness fetch codecs authenticate encrypted records against the provisioned identity,
mailbox, activation digest, canonical book entry, ciphertext hash and low-S signature.
The shared body verifier checks exact framing, epoch, slot, payment terms and the
preimage hash. It accepts already decrypted bytes and does not itself establish AEAD
provenance. The native `decrypt_ffor_witness_record` adapter uses the existing secp256k1,
HKDF-SHA256 and ChaCha20-Poly1305 implementations to verify the key, associated data and
authentication tag before exposing a receipt. Its Debug output redacts the preimage.
Witness observation amounts and timestamps carry no payment authority. This helper
borrows the caller's epoch key; protected key storage, durable receipt retention and
monitor reconciliation remain runtime responsibilities.

Public read-only receiver contexts let an application join protected records to native
history. Historical contexts expose authenticated setup, exact activation messages,
original funding and commitment identities, and a stable digest which survives ACK,
close, channel removal and restart. They do not assert a current phase. Active contexts
are opaque observations tied to this manager instance and the exact completed persistence
requirement. Capture checks the live Active fence, original commitment pair, signed ACK,
absence of close intent and absence of conflicting reconnect state. Close, removal,
conflict or restore invalidates an old observation. A point-in-time validation call does
not authorize later work; the future driver must recheck under its transition locks.
A retained Active phase can outlive the settlement deadline, so neither context grants
provisioning permission or invoice readiness.

These are consistency checks, not an authenticated storage envelope. Arbitrarily
deleting a mismatching add's ownership record after abort can make its nonreserved
hash indistinguishable from an ordinary post-abort payment. No valid writer creates
that state: the ownership record and stock HTLC are written together. The current
checks do not claim to detect every arbitrary alteration of local storage.
Similarly, an archive without its original live channel cannot independently prove
the historical funding context against arbitrary local storage alteration.

No feature bit, production custom-message transport, invoice readiness or background
deadline service is implemented here. The facade rechecks deadlines before new Init,
Accept, STFU and activation work; its caller must continue advancing and may cancel
a stalled pre-activation setup. Cancellation of an owned STFU handshake requests a
native disconnect. Automatic voucher failures wait for controlled release after the
abort revision is durable.
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
frozen reconnect handling and force-close. Activation recovery tests use real committed
channels and signed transcripts, exercise retained evidence after closure, and reject
missing monitors, mismatched commitment identities, downgrade attempts and substituted
transcripts. Capacity tests reload a registry with competing admissions and retain a
maximum signed acknowledgement from its reserved allowance. Reconnect tests retain
stock counter and revocation-secret checks, classify absent or conflicting reports,
and exercise signed acknowledgement loss across reload. Manager tests cover signer
refusal, exact retry, phase-specific write barriers, height changes, staged reports,
disconnect, force-close and terminal abort replay. Eight drain scenarios use two
actual vouchers in both funding directions, with no known preimage, a known preimage,
a delayed preimage monitor write, or restart after abort release. They check actual
fulfill and fail messages, both empty commitment sets, tombstone reload and a later
ordinary payment.

Cooperative close tests cover ten two-voucher scenarios across both funders, including
signed settled preimages, an already known unset-bit preimage, delayed monitor writes,
and restart after a signed removal flight is lost. They verify normal BOLT retransmission,
matching Active close replay, same-connection drain refusal, final monitor proof, retained
ACK replay and Closed release before ordinary payments. Native claim tests cover preimage
priority over unsent failures and monitor persistence after an already signed failure.
Force-close during unresolved drain retains exact archive evidence and monitor preimages
after reload, while missing-monitor recovery is rejected. Conflicting reconnect state
cannot release a close message.
Archive tests reject phase skips, changed signatures, wrong bitmaps, preimages and completion
metadata while preserving maximum-message transition capacity through competing admissions.

Read-only context tests cover both funders, absent ACK, pending and current persistence,
foreign/restored manager rejection, offline Active observation, conflicting reconnect,
and stable historical binding through close and archive-only force-close recovery.

The setup facade tests use real two-node channels in both funding directions. They
cover pending or failed storage, exact backpressure retries, synchronous Accept followed
immediately by stock voucher frames, and a crash after monitor persistence but before
accepted-manager persistence. Other cases cover pre-Accept adds, contradictory signed
replies, deadline crossing, retry identity after restore, missing archive evidence,
capacity refusal, witness policy, cancellation and normal payment after controlled
gate release on a fresh connection.

The lifecycle facade tests advance through real voucher and STFU rounds, durable
activation, close, both settled and failed drain, and final Closed in both funding
directions. They cover delayed monitor writes, exact retries, sent or unsent activation
expiry, signed Abort while activation is ambiguous, lost acknowledgements and late
recovery, stale generations, conflicting reports, and close replay followed by a fresh
connection. Both Closed serialization boundaries reload, and ordinary payment works
after the final completion releases the request gate. Owned-STFU cancellation before
abort persistence cannot send voucher failures after an early reconnect.

Native witness tests use four pinned Beignet records to compare ECDH, HKDF, plaintext and
preimages; they reject signed ciphertext, ephemeral-key, AAD, manifest and plaintext-term
substitution. The shared crate separately covers all six reference scenarios and arbitrary
body bytes. These tests do not exercise production witness transport or key storage.

## Next boundary

Reusable epochs require durable retired epoch IDs and voucher hashes, with one
current signed transcript record under the same channel authority. The public facade
now composes the native activation and cooperative-close transitions. Production
orchestration must retain witness keys and receipts, reconcile every recovered preimage
through the stock monitor, and enforce the configured deadline before claim safety ends.

Production transport must bind the receiver facade to actual authenticated
connections and deliver acknowledgement retries in the required order. Durable witness
mailbox recovery, preimage reconciliation, deadline enforcement and invoice eligibility remain
separate required boundaries. None can be inferred from durable setup, activation or
a successful private protocol test.
