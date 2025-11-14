#!/bin/bash
set -e

echo "Running pre-push CI validation..."

# Ensure folder exists but DO NOT overwrite logs (tests rely on real data)
mkdir -p logs

# Only create files if missing, do NOT empty them
[ ! -f logs/nodeA.log ] && touch logs/nodeA.log
[ ! -f logs/nodeB.log ] && touch logs/nodeB.log
[ ! -f logs/nodeC.log ] && touch logs/nodeC.log
[ ! -f logs/trusted_peers.json ] && echo "[]" > logs/trusted_peers.json

cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
RUST_TEST_THREADS=1 cargo test --all || { echo "❌ Tests failed — check logs/"; exit 1; }
cargo audit
cargo deny check licenses

echo "✅ All checks passed! Safe to push"
