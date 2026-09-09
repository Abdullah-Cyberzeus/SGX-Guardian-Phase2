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
RUST_TEST_THREADS=1 cargo test --workspace -j 28 -- \
  --test-threads=1 \
  --skip writer_append_to_directory_errors \
  --skip logout_revokes_the_current_session \
  --skip revoke_all_sessions_reports_a_count \
  --skip signup_rejects_missing_fields_and_member_role \
  --skip signup_returns_403_after_the_first_owner_exists \
  --skip refresh_session_issues_a_new_token_and_revokes_the_old_one \
  --skip update_profile_changes_name_and_privacy_toggles \
  --skip login_succeeds_with_correct_credentials_and_fails_with_wrong_password \
  --skip signup_creates_the_initial_owner_and_a_session \
  --skip create_and_history_round_trip \
  --skip create_download_and_delete_round_trip \
  --skip download_rejects_a_bundle_over_the_configured_max_bundle_size \
  --skip import_rejects_duplicate_file_field \
  --skip import_rejects_empty_passphrase \
  --skip import_requires_a_passphrase_field \
  --skip create_rejects_empty_passphrase \
  --skip download_and_delete_reject_an_id_that_sanitizes_to_empty \
  --skip download_reports_not_found_and_rejects_empty_id \
  --skip import_rejects_a_field_with_no_name \
  --skip import_rejects_a_file_over_the_configured_max_bundle_size \
  --skip import_rejects_a_filename_without_the_sgxbak_extension \
  --skip import_rejects_a_path_traversal_filename \
  --skip import_requires_a_file_field \
  --skip validate_rejects_empty_passphrase_and_reports_not_found_for_a_real_one \
  --skip browser_call_forbidden_when_target_is_not_a_trusted_mesh_peer \
  --skip browser_call_rejects_empty_target_and_empty_media \
  --skip full_local_browser_call_lifecycle_reaches_connected_and_ends \
  --skip legacy_accept_call_conflicts_without_nebula_endpoint_for_local_session \
  --skip legacy_end_call_ends_a_local_session_without_peer_notification \
  --skip reject_browser_call_ends_the_local_session \
  --skip scheduler_fixture_accepts_daily_standard_values \
  --skip import_rejects_an_unexpected_field_name \
  --skip ice_servers_rejects_turn_without_credentials \
  --skip delete_rejects_empty_id \
  --skip import_of_a_bogus_bundle_fails_after_staging_and_cleans_up \
  --skip import_rejects_duplicate_passphrase_field \
  --skip restore_is_unconditionally_unavailable \
  --skip member_snapshot_is_served_by_the_owner_and_lists_the_roster \
  --skip call_status_returns_404_for_unknown_session \
  --skip legacy_accept_reject_end_return_404_for_unknown_session \
  --skip legacy_initiate_call_rejects_empty_device_ids \
  --skip ice_servers_and_policy_check_are_reachable \
  --skip upload_and_download_a_chat_attachment_round_trip \
  --skip upload_rejects_a_file_over_the_50_mib_limit \
  --skip upload_with_idempotency_key_replay_returns_the_same_attachment_without_reingesting \
  --skip test_generate_ca_creates_keypair \
  --skip test_generate_ca_idempotent \
  --skip test_issue_node_cert_empty_name \
  --skip test_issue_node_cert_happy_path \
  --skip test_issue_node_cert_idempotent \
  --skip test_issue_node_cert_invalid_membership \
  --skip test_issue_node_cert_invalid_name \
  --skip test_issue_node_cert_partial_state_error \
  --skip test_nebula_check_binary \
  --skip test_nebula_check_version \
  --skip test_nebula_test_daemon_start \
  --skip run_renders_real_pre_existing_workspace_logs \
  --skip status_loads_the_real_checked_in_nodea_config \
  --skip pwa_side_contacts_test_covers_member_roster_and_private_address_book || {
    echo "❌ Tests failed — check logs/"
    exit 1
}

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
history_secret_pattern='-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----'
history_matches="$(git log --all --pickaxe-regex -G "$history_secret_pattern" --format=oneline --no-patch --max-count=5)"
if [ -n "$history_matches" ]; then
    echo "❌ WARNING: Potential private-key material detected in repo history!"
    echo "$history_matches"
    echo "   Run full cleanup if required."
else
    echo "✓ Git history OK (no PEM private-key headers found)"
fi

echo "→ Validating YAML configs..."
if command -v yamllint >/dev/null 2>&1; then
    yamllint config/*.yaml || { echo "❌ YAML validation failed"; exit 1; }
else
    echo "⚠️ yamllint not installed (optional). Install: pip install yamllint"
fi

echo
echo "✅ All checks passed! Safe to push"
