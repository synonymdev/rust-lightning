#!/usr/bin/env bash
set -euo pipefail

# Check runtime dependencies separately from property-test and fixture dependencies.
# Resolve and vendor with stable Cargo because Cargo 1.63 predates the sparse index.
crate_dir="$(cd "$(dirname "$0")/.." && pwd)"
check_dir="$(mktemp -d "${TMPDIR:-/tmp}/lightning-ffor-msrv.XXXXXX")"
trap 'rm -rf "$check_dir"' EXIT

if [ -n "${FFOR_MSRV_BIN:-}" ]; then
    msrv_cargo="$FFOR_MSRV_BIN/cargo"
    msrv_rustc="$FFOR_MSRV_BIN/rustc"
else
    msrv_cargo="$(rustup which --toolchain 1.63.0 cargo)"
    msrv_rustc="$(rustup which --toolchain 1.63.0 rustc)"
fi

cp -R "$crate_dir/src" "$check_dir/src"
sed '/^\[dev-dependencies\]/,$d' "$crate_dir/Cargo.toml" > "$check_dir/Cargo.toml"
printf '\n[workspace]\n' >> "$check_dir/Cargo.toml"
cd "$check_dir"
cargo +stable generate-lockfile
# Later build-tool releases require Rust 1.65; neither pin changes runtime APIs.
cargo +stable update -p cc --precise 1.2.67
cargo +stable update -p find-msvc-tools --precise 0.1.9
mkdir .cargo
cargo +stable vendor --locked vendor > .cargo/config.toml
# Version 4 uses the same entries here, but Cargo 1.63 accepts lockfile version 3.
python3 - <<'PY'
from pathlib import Path
lockfile = Path("Cargo.lock")
lockfile.write_text(lockfile.read_text().replace("version = 4\n", "version = 3\n", 1))
PY

"$msrv_rustc" --version
RUSTC="$msrv_rustc" "$msrv_cargo" check --lib --no-default-features --locked --offline
RUSTC="$msrv_rustc" "$msrv_cargo" check --lib --locked --offline
