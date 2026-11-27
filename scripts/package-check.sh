#!/usr/bin/env bash
# Build the published package, not the working tree: unpack the .crate
# outside the workspace and check it with every feature. Fails when a file a
# feature needs is left out of the package (the `include` allowlist, a path).
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
cargo package --locked --no-verify --allow-dirty -p asx >/dev/null
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
tar -xzf "target/package/asx-$version.crate" -C "$dir"
CARGO_TARGET_DIR="$dir/target" cargo check --locked --all-features \
    --manifest-path "$dir/asx-$version/Cargo.toml"
echo "package: asx $version builds from its .crate with every feature"
