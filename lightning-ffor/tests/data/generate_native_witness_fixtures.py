#!/usr/bin/env python3
"""Export two pinned Beignet scenarios for native tests without a JSON dependency."""

import hashlib
import json
from pathlib import Path


def main():
    source = Path(__file__).resolve().parent
    setup_bytes = (source / "appendix-d.json").read_bytes()
    setups = json.loads(setup_bytes)
    manifests = json.loads((source / "beignet-witness.json").read_text())
    records = json.loads((source / "beignet-witness-fetch.json").read_text())
    assert records["source_revision"] == "8aee31d18e596fe49a0d195b325a6e757d7a009b"
    assert records["appendix_d_sha256"] == hashlib.sha256(setup_bytes).hexdigest()
    assert manifests["appendix_d_sha256"] == records["appendix_d_sha256"]
    groups = []
    for setup, manifest, scenario in zip(setups[:2], manifests["fixtures"], records["fixtures"]):
        assert setup["scenario"] == manifest["scenario"] == scenario["scenario"]
        for record in scenario["records"]:
            values = {
                "scenario": setup["scenario"],
                "init": setup["init_wire"],
                "accept": setup["accept_wire"],
                "manifest": manifest["manifest"],
                "record": record["record"],
                "body": record["body"],
                "shared_hash": record["shared_hash"],
                "body_key": record["body_key"],
            }
            groups.append("\n".join(f"{key}={value}" for key, value in values.items()))
    destination = source.parents[2] / "lightning/src/ln/ffor/witness/fixtures.txt"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n\n".join(groups) + "\n")


if __name__ == "__main__":
    main()
