//! Public-API integration tests for the feature layer (PLACEHOLDER).
//!
//! NOTE: this is NOT a duplicate of D3's unit tests. Those already exist,
//! are complete, and pass (`src/features.rs`, `mod tests` — rate
//! conversion, gauge passthrough, counter-reset safety, EWMA convergence,
//! EWMA seeding/alpha-weighting, schema checks). Those stay where they are.
//!
//! This file is reserved (per the plan's Part B.2 project layout) for
//! *integration*-level checks that only make sense once later deliverables
//! exist — i.e. exercising `FeatureExtractor` only through the crate's
//! public API, driven by real sources instead of hand-built `RawSample`s:
//!   - D4's real `ScrapeSource` (board `/proc`, metrics, logs) feeding the
//!     extractor, once hardware access exists.
//!   - D8's collected baseline CSVs, to confirm the extractor produces
//!     sane, NaN-free 19-vectors across real recorded data at scale.
//!
//! Both are blocked today (no board access yet, D8 hasn't started), so
//! this stays an intentional empty placeholder rather than a real test —
//! it should not be filled in with a re-statement of the D3 unit tests
//! just to have something here.

#[test]
fn placeholder_reserved_for_public_api_feature_integration_tests() {
    // Intentionally empty. See module docs above.
    // Fill in once D4's ScrapeSource or D8's collected data exists.
}
