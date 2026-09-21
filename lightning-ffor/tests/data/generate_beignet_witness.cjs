// Deterministic Appendix F provisioning fixtures using the pinned Beignet codecs.
// Usage: TS_NODE_PROJECT=/path/to/beignet/tsconfig.json node \
//   -r /path/to/beignet/node_modules/ts-node/register generate_beignet_witness.cjs \
//   /path/to/beignet /path/to/appendix-d.json /path/to/output.json
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const reference = path.resolve(process.argv[2]);
const revision = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: reference, encoding: 'utf8' }).trim();
if (revision !== '8aee31d18e596fe49a0d195b325a6e757d7a009b') {
    throw new Error('Beignet revision differs from the fixture baseline');
}
const codecs = require(path.join(reference, 'src/lightning/ffor/witness-messages.ts'));
const { decodeVoucherBook } = require(path.join(reference, 'src/lightning/ffor/transcript.ts'));
const { getPublicKey } = require(path.join(reference, 'src/lightning/crypto/ecdh.ts'));
const source = fs.readFileSync(process.argv[3]);
const inputs = JSON.parse(source.toString());
// Public deterministic test material only. No wallet or channel signing keys are used.
const fetchSecret = Buffer.alloc(32, 42);
const fetchPublic = getPublicKey(fetchSecret);
const encryptionPublic = getPublicKey(Buffer.alloc(32, 44));
const witness = getPublicKey(Buffer.alloc(32, 43));
function wire(type, body) {
    const prefix = Buffer.alloc(2);
    prefix.writeUInt16BE(type);
    return Buffer.concat([prefix, body]).toString('hex');
}
const fixtures = inputs.map((input, i) => {
    const book = Buffer.from(input.book, 'hex');
    const entries = decodeVoucherBook(book).entries;
    const retentionUntil = entries[0].voucherExpiry + 144;
    const requestId = Buffer.alloc(16, i + 1);
    const fields = {
        version: 1, profile: 1, mailboxId: Buffer.alloc(32, i + 11),
        tSetup: Buffer.from(input.setup_hash, 'hex'),
        hCommit: Buffer.from(input.commitment_hash, 'hex'),
        epochStartHeight: 790000, hAct: Buffer.from(input.activation_hash, 'hex'),
        fetchPubkey: fetchPublic, encPubkey: encryptionPublic,
        retentionUntil, minReceipts: 0, book
    };
    const unsigned = codecs.encodeManifestUnsigned(fields);
    const manifest = codecs.signManifest(fields, fetchSecret);
    if (!codecs.verifyManifest(manifest, codecs.decodeManifest(manifest))) {
        throw new Error('Generated manifest did not authenticate');
    }
    return {
        scenario: input.scenario,
        unsigned: unsigned.toString('hex'),
        digest: codecs.manifestDigest(unsigned).toString('hex'),
        manifest: manifest.toString('hex'),
        provision: wire(55055, codecs.encodeWitnessProvision(requestId, manifest)),
        acknowledgement: wire(55057, codecs.encodeWitnessAck({
            requestId, ok: true, witnessNodeId: witness, retentionUntil
        })),
        refusal: wire(55057, codecs.encodeWitnessAck({
            requestId, ok: false, error: 'cannot reserve'
        }))
    };
});
fs.writeFileSync(process.argv[4], JSON.stringify({
    source_revision: revision,
    specification_revision: 'd719161f42d1eeb6bd6c3856d564222f03c2205e',
    source_file: 'src/lightning/ffor/witness-messages.ts',
    appendix_d_sha256: crypto.createHash('sha256').update(source).digest('hex'),
    fetch_public_key: fetchPublic.toString('hex'),
    encryption_public_key: encryptionPublic.toString('hex'),
    witness_public_key: witness.toString('hex'),
    fixtures
}, null, 2) + '\n');
