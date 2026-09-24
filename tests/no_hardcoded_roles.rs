//! P0.8 — the guard that stops role-by-name creeping back into `src/`.
//!
//! Phase 0 removed the three literals that pinned the product to one shape: the
//! CA was whichever Guardian was named `nodeA`, the circle was always
//! `guardian-circle-alpha`, and the overlay was always `192.168.100.0/24`. That
//! is easy to reintroduce one call site at a time, so this test fails the build
//! the moment it happens.
//!
//! ## Why this is not a `grep`
//!
//! A line-oriented search cannot tell production code from a test fixture, and
//! `docs/Guardian_Mesh_Enrollment_Complete_Plan.md` §P0.6 explicitly exempts
//! tests: a test that hardcodes `nodeA` is naming its own fixture, not encoding
//! a role. So each file is cut at its first `#[cfg(test)]` and only the part
//! before it is checked. That is the same measurement the plan's §9 baseline
//! uses, so the two numbers stay comparable.
//!
//! ## The allow-list
//!
//! * `src/mesh/legacy.rs` — the one module whose *job* is the old names. It
//!   maps a pre-Phase-0 install onto a `MeshProfile`, holds the legacy circle
//!   id and overlay, and keeps the name→port map that config files written
//!   before `ports:` still depend on.
//! * `src/testkit/` and `src/bin/test_*` — test harnesses that happen to live
//!   under `src/`. They are fixtures by definition; `testkit` exists to build
//!   servers for tests, and its default node id is a fixture value.

use std::path::{Path, PathBuf};

/// Paths whose production halves may contain the legacy literals, with the
/// reason each is allowed. A prefix match, so a directory covers its contents.
const ALLOWED: &[(&str, &str)] = &[
    (
        "src/mesh/legacy.rs",
        "owns the pre-Phase-0 → MeshProfile migration and the legacy constants",
    ),
    (
        "src/testkit/",
        "test harness shipped under src/; its node ids are fixtures",
    ),
    (
        "src/bin/test_",
        "test-only binary; its node ids are fixtures",
    ),
];

/// The literals that encode a role, a circle or a subnet as a name.
///
/// The overlay prefix is checked as `192.168.100.` (with the trailing dot) so
/// the bare CIDR inside `mesh::legacy` is the only spelling that needs the
/// allow-list, and an accidental `192.168.1004` never matches.
const FORBIDDEN: &[(&str, &str)] = &[
    (
        "\"nodeA\"",
        "role by node name — use mesh::profile::is_ca() or mesh::ca_guardian_id()",
    ),
    (
        "guardian-circle-alpha",
        "hardcoded circle id — use mesh::circle_id()",
    ),
    (
        "\"192.168.100.",
        "hardcoded overlay address — use mesh::overlay_host()/overlay_prefix()",
    ),
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn is_allowed(rel: &str) -> bool {
    ALLOWED.iter().any(|(prefix, _)| rel.starts_with(prefix))
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// One offending line.
struct Violation {
    file: String,
    line: usize,
    text: String,
    literal: &'static str,
    guidance: &'static str,
}

/// Everything before a file's first `#[cfg(test)]`.
///
/// Deliberately the *first* occurrence: a file with several test modules still
/// has all of its production code above the first one, and treating anything
/// after it as test code is the conservative choice — it can only make this
/// guard miss a violation, never invent one.
fn production_lines(source: &str) -> impl Iterator<Item = (usize, &str)> {
    let cut = source
        .lines()
        .position(|line| line.contains("#[cfg(test)]"))
        .unwrap_or(usize::MAX);
    source
        .lines()
        .enumerate()
        .take_while(move |(i, _)| *i < cut)
        .map(|(i, line)| (i + 1, line))
}

fn scan() -> Vec<Violation> {
    let root = repo_root();
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    files.sort();

    let mut violations = Vec::new();
    for file in files {
        let rel = file
            .strip_prefix(&root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");

        // `src/**/tests/` and `*tests.rs` are test modules by convention.
        if rel.contains("/tests/") || rel.ends_with("tests.rs") || is_allowed(&rel) {
            continue;
        }

        let Ok(source) = std::fs::read_to_string(&file) else {
            continue;
        };
        for (number, text) in production_lines(&source) {
            for (literal, guidance) in FORBIDDEN {
                if text.contains(literal) {
                    violations.push(Violation {
                        file: rel.clone(),
                        line: number,
                        text: text.trim().to_string(),
                        literal,
                        guidance,
                    });
                }
            }
        }
    }
    violations
}

#[test]
fn production_code_does_not_hardcode_roles_circles_or_the_overlay() {
    let violations = scan();
    if violations.is_empty() {
        return;
    }

    let mut report = format!(
        "\n{} hardcoded role/circle/overlay literal(s) found in production code.\n\
         Phase 0 removed these so a Guardian's role comes from its mesh profile\n\
         rather than its name. See docs/Guardian_Mesh_Enrollment_Complete_Plan.md §P0.6.\n\n",
        violations.len()
    );
    for v in &violations {
        report.push_str(&format!(
            "  {}:{}\n    {}\n    found {} — {}\n\n",
            v.file,
            v.line,
            v.text.chars().take(120).collect::<String>(),
            v.literal,
            v.guidance
        ));
    }
    report.push_str(
        "If a literal genuinely belongs to legacy compatibility, put it in\n\
         src/mesh/legacy.rs and call it from there. Widening ALLOWED in this\n\
         test is almost never the right fix.\n",
    );
    panic!("{report}");
}

#[test]
fn the_allow_list_only_names_paths_that_exist() {
    // A stale allow-list entry silently stops guarding a real directory, so a
    // renamed or deleted path must fail here rather than quietly weaken the
    // check. `src/bin/test_` is a filename prefix, so it is matched by scan.
    let root = repo_root();
    for (prefix, reason) in ALLOWED {
        if prefix.ends_with('/') || prefix.ends_with(".rs") {
            assert!(
                root.join(prefix).exists(),
                "allow-listed path {prefix} ({reason}) no longer exists — remove the entry"
            );
        }
    }
}

#[test]
fn the_legacy_module_is_the_only_place_that_still_holds_the_old_names() {
    // The plan tracks progress by this allow-list shrinking. If `mesh/legacy.rs`
    // ever stops containing the names, the migration is dead code and should be
    // removed along with this guard — so assert it still does its job.
    let legacy = std::fs::read_to_string(repo_root().join("src/mesh/legacy.rs"))
        .expect("src/mesh/legacy.rs must exist — it owns the legacy migration");
    assert!(
        legacy.contains("\"nodeA\""),
        "mesh::legacy no longer maps the pre-Phase-0 CA name; if legacy support \
         was dropped, delete this guard too"
    );
    assert!(
        legacy.contains("guardian-circle-alpha"),
        "mesh::legacy no longer holds the pre-Phase-0 circle id"
    );
}

#[test]
fn the_guard_reads_only_the_code_above_the_first_test_module() {
    // Protects the measurement itself: if `production_lines` regressed to
    // scanning whole files, the baseline in §9 of the plan would stop matching
    // and every fixture in the tree would become a false positive.
    let source = "let ca = \"nodeA\";\n#[cfg(test)]\nmod tests { let x = \"nodeA\"; }\n";
    let found: Vec<_> = production_lines(source).collect();
    assert_eq!(found.len(), 1, "only the line above #[cfg(test)] is production");
    assert_eq!(found[0].0, 1);

    // A file with no test module is production from top to bottom.
    let plain = "one\ntwo\nthree\n";
    assert_eq!(production_lines(plain).count(), 3);
}
