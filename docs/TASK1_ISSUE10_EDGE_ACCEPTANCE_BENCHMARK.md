# Task 1 Issue #10 - Edge / Board Acceptance Benchmark

Issue #10 verifies that the Task 1 model can stay inside embedded hardware limits.

What this adds:

- Loads the real exported Task 1 Isolation Forest model artifact.
- Checks model artifact size against the 10 MiB limit.
- Scores thousands of samples and records latency statistics.
- Saves a machine-readable JSON report.
- Marks laptop validation separately from real board validation.

Laptop results are not claimed as final board acceptance. Run the same command on the board to close the hardware part.

## Local Command

Run from `crates/sgx-anomaly-engine`:

```bash
cargo run --example run_task1_edge_acceptance_benchmark -- \
  --model data/nodeA_forest.json \
  --node nodeA \
  --samples 5000 \
  --out data/task1_edge_acceptance/nodeA_edge_benchmark.json
```

## Board Command

Run from `crates/sgx-anomaly-engine` on the target board:

```bash
cargo run --release --example run_task1_edge_acceptance_benchmark -- \
  --model data/nodeA_forest.json \
  --node nodeA \
  --samples 5000 \
  --out data/task1_edge_acceptance/nodeA_edge_benchmark.json \
  --target-profile board \
  --require-board
```

## Output File

```text
crates/sgx-anomaly-engine/data/task1_edge_acceptance/nodeA_edge_benchmark.json
```

## Verdict Meaning

- `pass`: model size and latency passed on the real board.
- `pass_for_current_machine_pending_target_board`: laptop/dev machine passed, board validation still pending.
- `fail`: model size or latency failed.
