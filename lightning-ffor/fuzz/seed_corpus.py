"""Seed protocol fuzzing with pinned public signed fixtures, without a signing key."""

import json
from pathlib import Path

crate = Path(__file__).resolve().parents[1]
corpus = crate / "fuzz" / "corpus" / "wire"
corpus.mkdir(parents=True, exist_ok=True)
fixtures = json.loads((crate / "tests/data/appendix-d.json").read_text())
for index, fixture in enumerate(fixtures):
    for field in ("init_wire", "accept_wire", "activate_wire", "ack_wire"):
        (corpus / f"appendix-{index}-{field}").write_bytes(bytes.fromhex(fixture[field]))
    init = bytes.fromhex(fixture["init_wire"])
    accept = bytes.fromhex(fixture["accept_wire"])
    (corpus / f"appendix-{index}-pair").write_bytes(len(init).to_bytes(2, "big") + init + accept)

reference = json.loads((crate / "tests/data/beignet-lifecycle.json").read_text())
for fixture in reference["fixtures"]:
    (corpus / fixture["name"]).write_bytes(bytes.fromhex(fixture["wire"]))
for fixture in reference["reestablish"]:
    (corpus / f"reestablish-{fixture['state']}").write_bytes(bytes.fromhex(fixture["value"]))

print("Seeded 35 signed reference messages/setup pairs and 7 reconnect reports")

witness_corpus = crate / "fuzz" / "corpus" / "witness"
witness_corpus.mkdir(parents=True, exist_ok=True)
witnesses = json.loads((crate / "tests/data/beignet-witness.json").read_text())
for index, (setup, witness) in enumerate(zip(fixtures, witnesses["fixtures"])):
    init = bytes.fromhex(setup["init_wire"])
    accept = bytes.fromhex(setup["accept_wire"])
    prefix = len(init).to_bytes(2, "big") + len(accept).to_bytes(2, "big") + init + accept
    for field in ("manifest", "provision"):
        (witness_corpus / f"witness-{index}-{field}").write_bytes(prefix + bytes.fromhex(witness[field]))
    for field in ("acknowledgement", "refusal"):
        (witness_corpus / f"witness-{index}-{field}").write_bytes(bytes.fromhex(witness[field]))
print("Seeded 24 witness manifest/provision/acknowledgement cases")

fetches = json.loads((crate / "tests/data/beignet-witness-fetch.json").read_text())
for index, fixture in enumerate(fetches["fixtures"]):
    init = bytes.fromhex(fixtures[index]["init_wire"])
    accept = bytes.fromhex(fixtures[index]["accept_wire"])
    manifest = bytes.fromhex(witnesses["fixtures"][index]["manifest"])
    prefix = len(init).to_bytes(2, "big") + len(accept).to_bytes(2, "big") + init + accept
    for field in ("first_request", "continuation_request", "odd_request", "first_response",
                  "continuation_response", "empty_response", "refusal"):
        (witness_corpus / f"fetch-{index}-{field}").write_bytes(bytes.fromhex(fixture[field]))
    for slot, record in enumerate(fixture["records"]):
        (witness_corpus / f"record-{index}-{slot}").write_bytes(bytes.fromhex(record["record"]))
        wire = bytes.fromhex(record["record"])
        candidate = len(manifest).to_bytes(2, "big") + len(wire).to_bytes(2, "big") + manifest + wire
        (witness_corpus / f"body-{index}-{slot}").write_bytes(prefix + candidate + bytes.fromhex(record["body"]))
print("Seeded fetch pages and signed encrypted records from all six reference scenarios")
