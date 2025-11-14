#!/bin/bash
echo "Starting 3 SGX Guardian nodes..."
echo "🧪 Cleaning old logs before multi-node test..."
# ensure logs directory exists
mkdir -p logs

# make glob expansion return empty list instead of literal pattern when no matches
shopt -s nullglob

# make sure jq is available
if ! command -v jq >/dev/null 2>&1; then
  echo "❌ jq is required but not installed. Install jq and retry."
  exit 1
fi
rm -f logs/nodeA.log logs/nodeB.log logs/nodeC.log 2>/dev/null
rm -f logs/trusted_peers.json logs/last_attestation.json 2>/dev/null
rm -f logs/trusted_peers_*.json 2>/dev/null

# Build once to avoid multiple cargo locks
cargo build >/dev/null 2>&1

# Run compiled binaries directly (avoids cargo exit noise)
./target/debug/sgx_guardian_client.exe nodeA 50051 > logs/nodeA.log 2>&1 &
pidA=$!
./target/debug/sgx_guardian_client.exe nodeB 50052 > logs/nodeB.log 2>&1 &
pidB=$!
./target/debug/sgx_guardian_client.exe nodeC 50053 > logs/nodeC.log 2>&1 &
pidC=$!
cleanup() {
  echo "🛑 Cleaning up nodes..."
  taskkill //PID $pidA //F > /dev/null 2>&1 || kill "$pidA" 2>/dev/null || true
  taskkill //PID $pidB //F > /dev/null 2>&1 || kill "$pidB" 2>/dev/null || true
  taskkill //PID $pidC //F > /dev/null 2>&1 || kill "$pidC" 2>/dev/null || true
}
trap cleanup EXIT
echo "✅ Nodes started: A=$pidA, B=$pidB, C=$pidC"

# --- Smart wait: up to 120 s or until we see at least 3 per-node peer files ---
echo "🕒 Waiting up to 120s for per-node peer files (trusted_peers_<pid>.json)..."
max_iter=24
found=0
for i in $(seq 1 $max_iter); do
  files=(logs/trusted_peers_*.json)
  # count only non-empty valid JSON files (array with at least one object)
  found=0
  for f in "${files[@]}"; do
    if [ -f "$f" ]; then
      # ensure it's valid JSON and is an array
      if jq -e 'if type=="array" then . else empty end' "$f" >/dev/null 2>&1; then
        # also ensure it is not an empty array
        if [ "$(jq 'length' "$f")" -gt 0 ]; then
          found=$((found+1))
        fi
      fi
    fi
  done
  if [ "$found" -ge 3 ]; then
    echo "✅ Found $found per-node peer files — proceeding."
    break
  fi
  sleep 5
done

if [ "$found" -lt 3 ]; then
  echo "⚠️ Timeout waiting for per-node peer files (found $found). Proceeding anyway."
fi
# --- Summaries ----------------------------------------------------
echo ""
echo "🧠 Checking results..."
echo "--------------------"
echo "Node A log summary:"
grep -E "Peer|Attesting|Verified|trusted|Policy|Circle" logs/nodeA.log | tail -15 || echo "No attestation logs."
echo "--------------------"
echo "Node B log summary:"
grep -E "Peer|Attesting|Verified|trusted|Policy|Circle" logs/nodeB.log | tail -15 || echo "No attestation logs."
echo "--------------------"
echo "Node C log summary:"
grep -E "Peer|Attesting|Verified|trusted|Policy|Circle" logs/nodeC.log | tail -15 || echo "No attestation logs."
echo "--------------------"
# --- Merge per-node peer files before inspection ------------------
echo "🧩 Merging peer files from all nodes..."
valid_files=()
for f in logs/trusted_peers_*.json; do
  # skip literal pattern if no matches (nullglob handles this) and skip single merged file
  [ -f "$f" ] || continue
  # skip the main merged file if accidentally present
  case "$f" in
    logs/trusted_peers.json) continue ;;
  esac
  # validate JSON is an array and non-empty
  if jq -e 'type == "array" and (length > 0)' "$f" >/dev/null 2>&1; then
    valid_files+=("$f")
  else
    echo "⚠️ Skipping invalid/empty file: $f"
  fi
done

if [ ${#valid_files[@]} -eq 0 ]; then
  echo "⚠️ No valid peer files found to merge."
else
  jq -s 'add | unique_by(.peer_id)' "${valid_files[@]}" > logs/trusted_peers.json \
    && echo "✅ Successfully merged ${#valid_files[@]} peer files." \
    || echo "❌ jq merge failed (check input files)."
fi
# --- Trusted peers inspection -------------------------------------
if [ -f logs/trusted_peers.json ]; then
  echo "Trusted Peers File:"
  cat logs/trusted_peers.json || echo "⚠️ Could not display file contents."
  echo ""
  echo "--------------------"
  echo "🔍 Verifying Circle of Trust..."
  peer_count=$(powershell -Command "(Get-Content 'logs/trusted_peers.json' | Select-String -Pattern 'peer_id').Count")
  if [ "$peer_count" -eq 3 ]; then
    echo "✅ Circle of Trust formed successfully — 3 peers verified."
  elif [ "$peer_count" -gt 3 ]; then
    echo "⚠️ Extra peers detected ($peer_count total) — check logs for duplicates."
  else
    echo "❌ Circle of Trust incomplete — only $peer_count peers trusted."
  fi
else
  echo "⚠️ trusted_peers.json not found — possibly ended before log flush."
fi

# --- Final demo banner --------------------------------------------
echo ""
echo "==============================="
if [ -f logs/trusted_peers.json ]; then
  if [ "$peer_count" -eq 3 ]; then
    echo "🎉 DEMO PASSED — Autonomous Circle of Trust formed successfully ✅"
  else
    echo "⚠️ DEMO PARTIAL — Some peers missing from Circle of Trust ❌"
  fi
else
  echo "❌ DEMO FAILED — No trusted peers file found."
fi
echo "==============================="
