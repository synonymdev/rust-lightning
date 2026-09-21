# Experimental FFOR receiver setup, activation and recovery

This fork targets rust-lightning v0.2.5. The current APIs provide receiver voucher
parking and verification of both commitment views for FFOR Variant D. Native manager
transitions compose activation, reconnect, pre-active abort and cooperative voucher drain
with ordered storage.
An experimental public receiver facade owns pre-init admission, synchronous peer input,
activation and cooperative close advancement. One immutable signed receiver invoice can
be assigned per supported epoch and released only through a guarded application
publication contract. Production transport orchestration, the application publication
runtime and payment outcome credit remain unfinished.

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
`validate_ffor_receiver_request_intent` additionally compares every original
preparation parameter, including ordered amounts and witness restriction, against
pending or accepted native history without requiring a peer connection. Exact
historical matches remain available after abort, expiry and channel removal. A
changed local ID, channel, peer or parameter is refused. `None` means no retained
history for that ID; a protected application record that was already bound must
refuse that missing history rather than treat absence as permission to prepare again.

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
invoking native monitor reconciliation remain runtime responsibilities.

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

Native witness registration now retains one immutable selection of one through four
witnesses before provisioning. The protected application store must first reserve
its recovery keys, exact signed manifests and receipt capacity. Registration compares
those manifests to the actual Active epoch, acknowledgement, frozen pair and current
settlement deadline. It stores compact public parameters, signatures and exact manifest
digests, reconstructing the canonical book from native history during validation.
Witness restrictions, separate mailbox/fetch identities and distinct fetch/encryption
keys are enforced. Exact retries retain the same selection and persistence requirement;
changed manifests or keys are refused. Required archive field 8 and schema 5 prevent
older readers from forgetting this ownership, including after channel removal.

Provision release requires a newly captured Active context after registration
persistence. The manager holds the actual settlement channel, archive, current height
and persistence locks while validating the exact typed Provision and invoking its
bounded enqueue callback. The callback must atomically check the authenticated witness
transport token and capacity, perform no I/O and acquire no native or store locks.
Settlement-peer connectivity is unnecessary. Backpressure permits exact request retry;
queue acceptance proves neither delivery nor witness acknowledgement. Restore requires
a fresh manager write and rejects an earlier instance's context. Historical registration
metadata remains inspectable after close or force-close, so missing sidecar keys cannot
be treated as permission to create a replacement selection. No invoice authority follows.

The stronger provisioning path stages an opaque attempt against the actual native
witness connection, exact registered manifest and request ID. Release rechecks the
current Active state and completed persistence, then marks the attempt sent only after
its paired transport callback accepts the bounded enqueue. Already sent retries do not
invoke the callback again. Disconnect and connection replacement invalidate attempts;
restore never recovers transient send authority. The manager retains at most 64 attempts
and request-ID tombstones without eviction until the corresponding witness disconnects.

Only a positive ACK correlated to a native sent attempt can enter native history.
The application first confirms its own protected ACK write, then passes the response
from the same authenticated connection to native retention. Native preserves its first
valid promise for each selected witness and returns a new persistence requirement.
Native and application history may retain different first request IDs after a crash
and fresh retry; both must bind the same epoch, manifest and witness with adequate
retention. Neither promise may be silently replaced to make their transport IDs match.

Required archive field 10 and schema 6 reserve a fixed 373 bytes for up to four native
promises before the stronger provisioning path is available. Filling a promise cannot
grow storage or enclosing length prefixes. Legacy witness registration needs an explicit
capacity-checked upgrade and successful write. Restore validates the complete record,
rejects noncanonical padding and imposes a fresh persistence barrier. Historical ACK
metadata survives close and removal but supplies no invoice or payment readiness.
The earlier observational Provision release cannot establish native sent correlation.

`ChannelMonitor::ffor_witness_receipt_snapshot` captures opaque evidence for one verified
receipt. The caller must drop its monitor guard before passing that snapshot, the receipt
and its historical context to `import_ffor_receiver_witness_receipt`. The manager checks
the original funding output, channel, settlement identity, canonical slot/hash/amount/D/E
and registered witness/mailbox/encryption key under the native peer and archive locks.
Receipt recovery remains valid after deadlines, disconnection, conflicting reports and
channel removal. Missing monitor ownership, stale counters and changed or pending funding
are refused. A closed channel's funding identity comes from its actual channel at removal
or its supplied durable monitor at restore, never from the receipt.

Live vouchers use the existing stock claim and monitor path without ordinary payment
metadata. Known preimages replace only failures that have not entered a commitment.
A late preimage for an already failed or removed voucher protects the original monitor
without reversing that outcome. The native holding cell, in-flight updates and monitor
own persistence and idempotence; the archive does not duplicate preimage storage.
`PendingMonitor` requires normal monitor completion processing and a fresh snapshot retry.
`MonitorPersisted` observes preimage protection under the application's Watch contract;
it is neither payment credit, successful settlement nor invoice readiness, and no ordinary
`PaymentClaimed` event is synthesized. As with all stock recovery, manager ReadArgs must
contain actual durable monitors. Encoding an in-memory monitor does not complete a failed
or outstanding write.

These are consistency checks, not an authenticated storage envelope. Arbitrarily
deleting a mismatching add's ownership record after abort can make its nonreserved
hash indistinguishable from an ordinary post-abort payment. No valid writer creates
that state: the ownership record and stock HTLC are written together. The current
checks do not claim to detect every arbitrary alteration of local storage.
Similarly, an archive without its original live channel cannot independently prove
the historical funding context against arbitrary local storage alteration.

No feature bit, production custom-message transport, application invoice publication
runtime or background deadline service is implemented here. The facade rechecks deadlines
before new Init, Accept, STFU and activation work; its caller must continue advancing and may cancel
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

## Invoice assignment and publication

The supported issuer uses a one-slot, non-hash-chained Variant D book. It derives amount,
payment hash, receiver identity, settlement fees, inbound alias and CLTV from native
ownership. The signed Init witness restriction must exactly match the registered and
durably acknowledged witness set.

The invoice has one W -> S -> R route hint and no MPP support. Native verifies the
public W-S announcement and directional update, signatures, distinct identities, canonical
endpoint ordering, enabled state, amount bounds, fees and freshness. These signatures
identify route terms; they do not prove current channel funding or liquidity. Private W-S
channels without authenticated route evidence are not supported. BOLT11 hints remain
advisory, with the signed witness restriction providing the honest settlement peer's
admission guard.

`prepare_ffor_receiver_invoice` signs outside locks. Native then rechecks the current
phase, frozen pair, deadline, route binding and completed persistence before retaining the
exact signed bytes. Requested expiry is capped using eight minutes per remaining block
before admission closes, less the explicit safety margin. The actual watched monitor is
locked through retention or final bounded publication, excluding pending off-chain
persistence, known preimages, funding spends, pending funding changes and local commitment
signing. The higher of manager and monitor height is used so delayed notifications cannot
extend admission. New issuance requires the std clock; no_std supports historical
decoding only.

`ffor_receiver_invoice_for_storage` returns exact bytes only after the latest native write
completes. It supports historical recovery after expiry or close and does not grant
display permission. The application must first durably confirm these bytes, the matching
Pending payment and its protected confirmation marker. `release_ffor_receiver_invoice`
then rechecks native and monitor state through `Watch::validate_and_publish_ffor_invoice`
and a callback that performs only bounded in-memory publication. Retry, failed publication
and restart cannot replace the assigned invoice. Custom Watch implementations default to
refusing this operation until they implement the actual-monitor boundary. Invoice
assignment adds required field 12 and archive schema 7, bounding the signed string to
4096 bytes and its record to 8192 bytes. The assignment is permanent after failed
publication, expiry or restart, and it is not a payment success signal.

## Cooperative outcome journal

A new drain initializes a versioned journal with one resolved bit and one fulfilled bit per
book slot, at most 483 slots and two 61-byte bitmaps. The stock revoke-and-ack removal of an
inbound LocalRemoved HTLC records the exact owned voucher's slot at the same point it adds a
fulfilled amount to the channel balance, without a new fallible step after the existing
commitment-round preflight. The journal is native accounting only. It is never derived from
the signed settled bitmap or from known preimages, and fulfilled is always a subset of
resolved. A preimage learned after a signed failure protects the monitor but leaves that slot
failed.

Restore validation requires exact bitmap lengths, zero padding, the subset rule and, for each
slot, either a resolved bit or the voucher still pending as a stock HTLC, never both; a
fulfilled slot must have a known preimage. The drain completion proof requires every slot
resolved and every signed settled slot fulfilled, binds the whole journal into a distinct
`ffor/native-drain-complete/v2` digest domain, and carries it into the retained ClosedDrain
under required-even field 14 with archive version 8. Legacy drains and archives without a
journal keep the original digest domain, remain readable, and never acquire invented outcomes.
Older readers reject journaled records with `UnknownRequiredFeature` instead of dropping them.
A journaled Closed proof also raises a close-only archive past the request version, and that
framing growth is charged inside the existing 512-byte terminal reservation.

`ffor_receiver_voucher_outcome` is a historical, manager-instance-bound getter keyed by the
current epoch context, the one-based slot, the exact payment hash and amount. It reports
Fulfilled or Failed only from a fully finalized journal after the latest native manager write
completed, including a fresh barrier after restore. Pending drains, force-closed epochs and
legacy absence return no outcome. It changes no balances and emits no events. On-chain
outcomes remain a separate unimplemented boundary: a future proof must join the stock
monitor's irrevocably resolved HTLC evidence to the actual confirmed funding spend, an owned
inbound voucher output, the original commitment identity and completed monitor persistence,
with explicit partially drained commitment and reorg analysis. A preimage or a generic
spendable output does not identify a payment.

## Validation

The current focused native suite passes 172 tests, including 13 invoice tests and the
cooperative outcome journal checks. Native no-default-features and documentation builds with
broken intra-doc links denied also pass.

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
Read-only intent tests check every preparation field, preserve pending write barriers,
and recover exact pending, promoted and archive-only histories after restart in both
funding directions where applicable.

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

Eight witness-registration tests cover both funders, missing acknowledgements, pending
manager and monitor writes, exact/reordered retries, stale manager contexts, disconnected
settlement peers, deadline crossings, conflicting reconnects and close refusal. Archive
checks cover compact four-witness ownership for a 483-slot book, remaining terminal
capacity, corrupted metadata, key reuse, missing required evidence and version downgrade.
An opt-in test exporter produces a real Active manager and stock monitor using a public
Node wallet seed for downstream integration tests; normal test runs do not write fixtures.

Nine native ACK tests cover both funders, unsent requests, backpressure, wrong witness,
request and retention, refusal tombstones, connection replacement, failed persistence,
exact retries, independent first promises, restoration and archive-only history. They
also check offline settlement-peer operation, current deadlines, fixed storage through
all terminal phases with a maximum book, legacy quota refusal and malformed archives.
A previous field-layout reader rejects the new required ACK field; schema downgrade is
also refused. These checks do not exercise a production witness.

Thirteen invoice tests cover every durable witness acknowledgement, exact retries, failed
and stale persistence, restored handles, wrong signers, signed route loops, missing or
additional witness permissions, archive corruption and capacity, monitor height ahead of
manager, known preimages without a counter change, funding spend before manager
notification, and actual monitor exclusion through publication. A genuine public-driver
fixture covers setup through witness registration and invoice assignment; it exposed a
runtime/height lock inversion in witness registration and release, which now use a
consistent registry, runtime, height and persistence order. An opt-in exporter writes that
fixture only when `FFOR_NODE_INVOICE_FIXTURE_DIR` is set.

Journal coverage extends the cooperative drain matrix across both funders, signed settled,
learned and failed slots, delayed monitors and restart mid-round: outcomes are absent before
the retained Closed proof, exact afterwards, refused for wrong slots, hashes and amounts,
absent again on a restored manager until its fresh write completes, and preserved as
archive-only history after the channel is force-closed away. A late receipt after a signed
failure reports Failed. A force-closed drain reports nothing. Archive tests cover the legacy
digest without a journal, journaled round trips at the maximum 483-slot book inside the
terminal reservation, replacement refusal, old readers, downgraded and future version bytes,
and malformed journals with the wrong domain, incomplete coverage, padding bits, fulfilled
bits outside resolved, the wrong slot count and a signed settled slot that stock accounting
never fulfilled. Drain tests cover legacy records restoring without a journal, never
acquiring one, and closed drains freezing theirs.

Seven receipt-import integration tests exercise both funders, delayed monitor persistence,
idempotent retries, crash recovery from a failed write using the prior durable monitor,
missing peer/monitor refusal, unregistered witnesses, changed identities, expired epochs,
conflicting reconnects and force-close. They drive queued failures into fulfills only when
the preimage arrives before commitment, preserve already signed failures, and test actual
Closed to splice to removal recovery without applying old-funding receipts to the new scope.
Receiver payment events remain absent. Seven ordinary splice tests and the stock force-close
failure test also pass. A separate opt-in request exporter writes genuine empty and pending
manager/monitor fixtures only when `FFOR_NODE_REQUEST_FIXTURE_DIR` is set.

## Next boundary

Reusable epochs require durable retired epoch IDs and voucher hashes, with one
current signed transcript record under the same channel authority. The public facade
now composes the native activation and cooperative-close transitions. Production
orchestration must retain witness keys and receipts, reconcile every recovered preimage
through the native import API to completed monitor protection, and enforce the configured
deadline before claim safety ends.

Production transport must bind the receiver facade to actual authenticated
connections and deliver acknowledgement retries in the required order. Durable witness
mailbox recovery, receipt-import orchestration, deadline enforcement, the application
invoice publication runtime, joining journaled outcomes to the application payment ledger and
on-chain outcomes remain separate required boundaries. None can be inferred from durable setup, activation or
a successful private protocol test.
