# Experimental FFOR receiver parking

This fork targets rust-lightning v0.2.5. The current APIs provide receiver voucher
parking and point-in-time verification of both commitment views for FFOR Variant D.
They do not provide an active offline receiving epoch.

`register_ffor_receiver_book` takes an already authenticated and validated public
book on an empty, connected, synchronized anchor channel. It checks the book's
structural invariants and exact first incoming HTLC ID. The application must persist
the registration before allowing the settlement peer to send vouchers. Registration
requests manager persistence but does not wait for a durable write.

The stock channel owns voucher identity through the ordinary commitment rounds.
Exact vouchers never enter invoice, keysend, or forwarding processing. The receiver
only derives encrypted failure material from their onion keys. `Registered` reports
progress; `Parked` additionally requires the complete monitor-backed commitment proof,
including both current commitment transactions and holder claim signatures.

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

These are consistency checks, not an authenticated storage envelope. Arbitrarily
deleting a mismatching add's ownership record after abort can make its nonreserved
hash indistinguishable from an ordinary post-abort payment. No valid writer creates
that state: the ownership record and stock HTLC are written together. The current
checks do not claim to detect every arbitrary alteration of local storage.

No feature bit, wire activation, invoice readiness, commitment freeze, or automatic
setup deadline is implemented here. The caller must abort a setup that times out.
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
Existing payment, reload, monitor, and quiescence suites also pass.
Three signer tests additionally verify the public Appendix D activation signature,
domain/type separation, local node identity, low-S output and default refusal.

## Next boundary

Reusable epochs require durable retired epoch IDs and voucher hashes, with one
current signed transcript record under the same channel authority. Activation must
atomically verify commitment evidence, record exact signed setup and activation
bytes, and freeze ordinary mutations. A manager persistence-completion barrier must
precede acknowledgement release or invoice eligibility. The record must also survive
channel removal and remain available during on-chain resolution, including witness
and mailbox recovery. None of these later guarantees can be inferred from parking.
