#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CRS_VERSION=4.28.0
CRS_SHA256=fca67fe46adafeeee61b9d1a03f38c25b9b2a799577df03fa51d99589e6d03b9
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if [[ -n "${CRS_SOURCE_DIR:-}" ]]; then
  SOURCE_DIR=$CRS_SOURCE_DIR
else
  ARCHIVE="$TMP/coreruleset-${CRS_VERSION}-minimal.tar.gz"
  curl -fsSL --retry 3 \
    "https://github.com/coreruleset/coreruleset/releases/download/v${CRS_VERSION}/coreruleset-${CRS_VERSION}-minimal.tar.gz" \
    -o "$ARCHIVE"
  printf '%s  %s\n' "$CRS_SHA256" "$ARCHIVE" | sha256sum -c -
  tar -xzf "$ARCHIVE" -C "$TMP"
  SOURCE_DIR="$TMP/coreruleset-${CRS_VERSION}/rules"
fi

python3 "$ROOT/tools/convert_crs.py" \
  --source-dir "$SOURCE_DIR" \
  --output-dir "$TMP/rules" \
  --version "$CRS_VERSION"

diff -ru \
  --exclude='engine.rss' \
  --exclude='engine_*.rss' \
  --exclude='ruleset_bundle.rss' \
  --exclude='pd_edge_waf.rss' \
  "$ROOT/rules" "$TMP/rules"
for bundle in engine_bundle.rss ruleset_bundle.rss pd_edge_waf.rss; do
  cp "$ROOT/rules/$bundle" "$TMP/$bundle"
done
python3 "$ROOT/tools/bundle_engine.py"
for bundle in engine_bundle.rss ruleset_bundle.rss pd_edge_waf.rss; do
  diff -u "$TMP/$bundle" "$ROOT/rules/$bundle"
done
python3 -m py_compile "$ROOT/tools/convert_crs.py" "$ROOT/tools/bundle_engine.py"
python3 "$ROOT/tools/test_convert_crs.py"
cargo fmt --all --manifest-path "$ROOT/Cargo.toml" -- --check
cargo test --release --manifest-path "$ROOT/Cargo.toml" --all-targets
