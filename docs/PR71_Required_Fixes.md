# PR #71 — Virtual-ID Required Fixes
> Branch: `feat/60_Virtual-ID` → `main`  
> CI: Build ✅ | CodeQL ✅ | All checks passed ✅  
> CodeRabbit: 2 Critical + 15 Minor + 8 Nitpick = 25 issues  
> **Only 2 Critical items — both recurring, both ⚡ Quick win**

---

## F-1 · attest_quote.rs composite_digest slice panic
- **Tool:** CodeRabbit · 🔴 Critical · ⚡ Quick win
- **Location:** [`sgx-pa-cli/src/commands/attest_quote.rs#L141-L144`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/60_Virtual-ID/sgx-pa-cli/src/commands/attest_quote.rs#L141-L144)

`&snap["composite_digest"].as_str().unwrap_or("?")[..16]` panics if the digest is shorter than 16 characters or missing. This runs AFTER the quote has been signed — a panic here loses the signed quote.

**Recurring from PR #46 (boot_status hash slice).**

**FIND:**
```rust
                    println!(
                        "  PCR composite: {}...",
                        &snap["composite_digest"].as_str().unwrap_or("?")[..16]
                    );
```

**REPLACE WITH:**
```rust
                    let composite = snap["composite_digest"].as_str().unwrap_or("?");
                    let preview: String = composite.chars().take(16).collect();
                    println!("  PCR composite: {}...", preview);
```

---

## F-2 · pcr_baseline.rs unwrap() panics on file read/parse
- **Tool:** CodeRabbit · 🔴 Critical · ⚡ Quick win
- **Location:** [`sgx-pa-cli/src/commands/pcr_baseline.rs#L237-L240`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/60_Virtual-ID/sgx-pa-cli/src/commands/pcr_baseline.rs#L237-L240)

Both `fs::read_to_string` and `serde_json::from_str` use `.unwrap()` — a corrupt or missing baseline/snapshot file will panic the CLI with an unhelpful stack trace instead of a user-friendly error.

**Recurring from PR #68/#69/#70.**

**FIND:**
```rust
    let baseline: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&bl_path).unwrap()).unwrap();
    let snapshot: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&pcr_path).unwrap()).unwrap();
```

**REPLACE WITH:**
```rust
    let baseline: serde_json::Value = match fs::read_to_string(&bl_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
    {
        Some(v) => v,
        None => {
            eprintln!("❌ Failed to load baseline from {}", bl_path);
            return;
        }
    };
    let snapshot: serde_json::Value = match fs::read_to_string(&pcr_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
    {
        Some(v) => v,
        None => {
            eprintln!("❌ Failed to load snapshot from {}", pcr_path);
            return;
        }
    };
```

---

# Apply Checklist
```
F-1:  sgx-pa-cli/src/commands/attest_quote.rs (1 location)
F-2:  sgx-pa-cli/src/commands/pcr_baseline.rs (1 location)

cargo build -p sgx-pa-cli --bin sgx-pa-cli
cargo test -- --nocapture --test-threads=1
```

**Total: 2 fixes · ~15 minutes · Regression risk: None**
