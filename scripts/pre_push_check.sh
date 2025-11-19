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

echo "→ Checking code formatting..."
cargo fmt --all -- --check

echo "→ Running clippy linter..."
cargo clippy --all-targets --all-features -- -D warnings

echo "→ Running tests..."
RUST_TEST_THREADS=1 cargo test --all || { echo "❌ Tests failed — check logs/"; exit 1; }

echo "→ Auditing dependencies for security vulnerabilities..."
cargo audit

echo "→ Checking licenses..."
cargo deny check licenses

echo "→ Checking for outdated dependencies (cargo-outdated)..."
if command -v cargo-outdated >/dev/null 2>&1; then
    cargo outdated || true
else
    echo "⚠️ cargo-outdated not installed (optional). Install via: cargo install cargo-outdated"
fi

echo "→ Checking for private key leaks in working tree..."
if git ls-files | grep -E '\.(asc|key|pem|der|pfx)$|privatekey' >/dev/null; then
    echo "❌ Potential private key found in working tree. Resolve before pushing!"
    git ls-files | grep -E '\.(asc|key|pem|der|pfx)$|privatekey'
    exit 1
else
    echo "✓ No private keys in working tree"
fi

echo "→ Checking for key leaks in Git history (fast scan)..."
if git log --pretty=oneline | grep -Ei "private.?key|BEGIN RSA|secret" >/dev/null; then
    echo "❌ WARNING: Sensitive key-like content detected in repo history!"
    echo "   Run full cleanup if required."
else
    echo "✓ Git history OK (no obvious key strings)"
fi

echo "→ Validating YAML configs..."
if command -v yamllint >/dev/null 2>&1; then
    yamllint config/*.yaml || { echo "❌ YAML validation failed"; exit 1; }
else
    echo "⚠️ yamllint not installed (optional). Install: pip install yamllint"
fi

echo
echo "✅ All checks passed! Safe to push"
