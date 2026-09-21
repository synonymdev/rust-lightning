// Reproduce Appendix F fetch and encrypted-record fixtures with pinned Beignet codecs.
// Usage: TS_NODE_PROJECT=/path/to/beignet/tsconfig.json node \
//   -r /path/to/beignet/node_modules/ts-node/register generate_beignet_witness_fetch.cjs \
//   /path/to/beignet /path/to/appendix-d.json /path/to/beignet-witness.json /path/to/output.json
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const reference = path.resolve(process.argv[2]);
const revision = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: reference, encoding: 'utf8' }).trim();
if (revision !== '8aee31d18e596fe49a0d195b325a6e757d7a009b') throw new Error('Reference revision mismatch');
const codecs = require(path.join(reference, 'src/lightning/ffor/witness-messages.ts'));
const encryption = require(path.join(reference, 'src/lightning/ffor/witness-crypto.ts'));
const curve = require(path.join(reference, 'src/lightning/crypto/ecdh.ts'));
const { hkdf } = require(path.join(reference, 'src/lightning/crypto/hkdf.ts'));
const { decodeVoucherBook } = require(path.join(reference, 'src/lightning/ffor/transcript.ts'));
const source = fs.readFileSync(process.argv[3]);
const setups = JSON.parse(source);
const provisions = JSON.parse(fs.readFileSync(process.argv[4]));
const sha = (...parts) => crypto.createHash('sha256').update(Buffer.concat(parts.map(x => typeof x === 'string' ? Buffer.from(x) : x))).digest();
function wire(type, bytes) { const b = Buffer.alloc(2); b.writeUInt16BE(type); return Buffer.concat([b, bytes]).toString('hex'); }
// Public deterministic fixture keys, matching the provisioning fixture generator.
const fetchSecret = Buffer.alloc(32, 42), witnessSecret = Buffer.alloc(32, 43), encSecret = Buffer.alloc(32, 44);
const fixtures = setups.map((setup, i) => {
    const manifest = codecs.decodeManifest(Buffer.from(provisions.fixtures[i].manifest, 'hex'));
    const book = decodeVoucherBook(manifest.book);
    const records = book.entries.slice(0, 3).map(entry => {
        const slot = Buffer.alloc(2); slot.writeUInt16BE(entry.k);
        const preimage = sha(`ffor/vector/${setup.scenario}/preimage`, slot);
        if (!sha(preimage).equals(entry.paymentHash)) throw new Error('Public vector preimage mismatch');
        const header = {
            version: 1, profile: 1, mailboxId: manifest.mailboxId,
            recordId: sha(`ffor/witness-fetch-fixture/${setup.scenario}/record`, slot),
            k: entry.k, hAct: manifest.hAct, termsHash: codecs.termsHash(entry),
            witnessNodeId: curve.getPublicKey(witnessSecret), encPubkey: manifest.encPubkey,
            recordedHeight: 790010, flags: entry.k % 2, ciphertextHash: Buffer.alloc(32)
        };
        const body = codecs.encodeRecordBody({
            epochId: book.epochId, k: entry.k, t: preimage, hK: entry.paymentHash,
            dK: entry.amountMsat, tExp: entry.voucherExpiry, d: entry.settlementDeadline,
            amountInMsat: entry.amountMsat + 6000n, amountOutMsat: entry.amountMsat,
            outgoingCltv: 791000, observedUnixTime: 1700000000n
        });
        const ephemeral = sha(`ffor/witness-fetch-fixture/${setup.scenario}/ephemeral`, slot);
        const savedRandom = crypto.randomBytes;
        let ciphertext;
        try {
            // Only this isolated deterministic fixture replaces randomness, never production code.
            crypto.randomBytes = length => { if (length !== 32) throw new Error('Unexpected draw'); return ephemeral; };
            ciphertext = encryption.sealRecordBody(manifest.encPubkey, codecs.recordAad(header), body);
        } finally { crypto.randomBytes = savedRandom; }
        header.ciphertextHash = sha(ciphertext);
        const record = { header, witnessSig: curve.sign(codecs.recordDigest(codecs.encodeRecordHeader(header)), witnessSecret), ciphertext,
            receipts: entry.k === 1 ? [] : [Buffer.from('opaque guardian attachment'), Buffer.from([0, 255])] };
        const encoded = codecs.encodeRecord(record);
        if (!codecs.verifyRecordSignature(codecs.decodeRecord(encoded))) throw new Error('Record signature mismatch');
        if (!encryption.openRecordBody(encSecret, codecs.recordAad(header), ciphertext).equals(body)) throw new Error('Reference AEAD mismatch');
        const verified = codecs.verifyWitnessRecord(record, {
            witnessNodeId: header.witnessNodeId, mailboxId: manifest.mailboxId, encPrivkey: encSecret
        }, book.entries, book.epochId, manifest.hAct);
        if (!verified.ok) throw new Error(verified.reason);
        const shared = curve.ecdh(ephemeral, manifest.encPubkey);
        return { record: encoded.toString('hex'), header: codecs.encodeRecordHeader(header).toString('hex'), aad: codecs.recordAad(header).toString('hex'),
            digest: codecs.recordDigest(codecs.encodeRecordHeader(header)).toString('hex'), ciphertext: ciphertext.toString('hex'), body: body.toString('hex'),
            shared_hash: shared.toString('hex'), body_key: hkdf(Buffer.alloc(0), shared, Buffer.from('ffor/witness/body'), 32).toString('hex') };
    });
    const id = Buffer.alloc(16, i + 31), nonce = Buffer.alloc(32, i + 61);
    const first = codecs.encodeWitnessFetch(id, manifest.mailboxId, nonce, fetchSecret);
    const after = codecs.encodeWitnessFetch(Buffer.alloc(16, i + 41), manifest.mailboxId, Buffer.alloc(32, i + 71), fetchSecret, 1);
    const tlv = Buffer.from([3, 1, 7]);
    const odd = Buffer.concat([id, manifest.mailboxId, nonce, curve.sign(codecs.fetchDigest(manifest.mailboxId, nonce, tlv), fetchSecret), tlv]);
    return { scenario: setup.scenario, records,
        first_request: wire(55059, first), first_digest: codecs.fetchDigest(manifest.mailboxId, nonce).toString('hex'),
        continuation_request: wire(55059, after), continuation_digest: codecs.fetchDigest(manifest.mailboxId, Buffer.alloc(32, i + 71), codecs.fetchTlv(1)).toString('hex'),
        odd_request: wire(55059, odd),
        first_response: wire(55061, codecs.encodeWitnessFetchResp({ requestId: id, ok: true,
            records: [codecs.decodeRecord(Buffer.from(records[0].record, 'hex'))], ...(records.length > 1 ? { nextAfterK: 1 } : {}) })),
        continuation_response: wire(55061, codecs.encodeWitnessFetchResp({ requestId: Buffer.alloc(16, i + 41), ok: true,
            records: records.slice(1).map(r => codecs.decodeRecord(Buffer.from(r.record, 'hex'))) })),
        empty_response: wire(55061, codecs.encodeWitnessFetchResp({ requestId: id, ok: true, records: [] })),
        refusal: wire(55061, codecs.encodeWitnessFetchResp({ requestId: id, ok: false, error: 'unavailable' })) };
});
fs.writeFileSync(process.argv[5], JSON.stringify({ source_revision: revision,
    specification_revision: 'd719161f42d1eeb6bd6c3856d564222f03c2205e',
    source_files: ['src/lightning/ffor/witness-messages.ts', 'src/lightning/ffor/witness-crypto.ts', 'src/lightning/crypto/ecdh.ts'],
    appendix_d_sha256: sha(source).toString('hex'), fixtures }, null, 2) + '\n');
