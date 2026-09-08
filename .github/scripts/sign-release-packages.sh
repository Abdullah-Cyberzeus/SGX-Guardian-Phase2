#!/usr/bin/env bash
set -euo pipefail

die() {
  echo "ERROR: $*" >&2
  exit 1
}

package_dir="${1:-}"
signed_dir="${2:-}"
[[ -d "$package_dir" ]] || die "Package directory does not exist: $package_dir"
[[ -n "$signed_dir" ]] || die "Signed artifact directory is required"
[[ -n "${RELEASE_GPG_PRIVATE_KEY:-}" ]] || die "RELEASE_GPG_PRIVATE_KEY is required"
[[ -n "${RELEASE_GPG_PASSPHRASE:-}" ]] || die "RELEASE_GPG_PASSPHRASE is required"
[[ "${RELEASE_GPG_FINGERPRINT:-}" =~ ^[0-9A-F]{40}$ ]] ||
  die "RELEASE_GPG_FINGERPRINT must be a canonical 40-character fingerprint"
command -v gpg >/dev/null 2>&1 || die "gpg is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"

mapfile -d '' deb_packages < <(find "$package_dir" -maxdepth 1 -type f -name '*.deb' -print0)
mapfile -d '' rpm_packages < <(find "$package_dir" -maxdepth 1 -type f -name '*.rpm' -print0)
mapfile -d '' manifests < <(
  find "$package_dir" -maxdepth 1 -type f -name 'release-manifest.txt' -print0
)
[[ "${#deb_packages[@]}" -eq 1 ]] ||
  die "Expected exactly one Debian package, found ${#deb_packages[@]}"
[[ "${#rpm_packages[@]}" -eq 1 ]] ||
  die "Expected exactly one RPM package, found ${#rpm_packages[@]}"
[[ "${#manifests[@]}" -eq 1 ]] ||
  die "Expected exactly one release manifest, found ${#manifests[@]}"

for package in "${deb_packages[@]}" "${rpm_packages[@]}"; do
  digest="$(sha256sum "$package" | awk '{print $1}')"
  grep -Fqx "package_sha256=$digest  $(basename "$package")" "${manifests[0]}" ||
    die "Release manifest digest does not match $(basename "$package")"
done

if [[ -d "$signed_dir" ]] && find "$signed_dir" -mindepth 1 -print -quit | grep -q .; then
  die "Signed artifact directory must be empty: $signed_dir"
fi
mkdir -p "$signed_dir"

umask 077
gnupg_home="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/guardian-gnupg.XXXXXX")"
trap 'rm -rf -- "$gnupg_home"' EXIT
export GNUPGHOME="$gnupg_home"

printf '%s' "$RELEASE_GPG_PRIVATE_KEY" | gpg --batch --yes --import
secret_key_records="$(gpg --batch --with-colons --fingerprint --fingerprint --list-secret-keys)"
mapfile -t primary_fingerprints < <(
  awk -F: '
    $1 == "sec" { primary = 1; next }
    primary && $1 == "fpr" { print $10; primary = 0 }
  ' <<<"$secret_key_records"
)
[[ "${#primary_fingerprints[@]}" -eq 1 ]] ||
  die "Private key input must import exactly one primary secret key"

mapfile -t signing_fingerprints < <(
  awk -F: '
    $1 == "sec" || $1 == "ssb" { signing = ($12 ~ /[sS]/); next }
    signing && $1 == "fpr" { print $10; signing = 0 }
  ' <<<"$secret_key_records"
)
matching_signing_keys=0
for fingerprint in "${signing_fingerprints[@]}"; do
  if [[ "$fingerprint" == "$RELEASE_GPG_FINGERPRINT" ]]; then
    matching_signing_keys=$((matching_signing_keys + 1))
  fi
done
[[ "$matching_signing_keys" -eq 1 ]] ||
  die "Configured fingerprint does not identify exactly one imported signing key"

for artifact in "${deb_packages[@]}" "${rpm_packages[@]}" "${manifests[@]}"; do
  destination="$signed_dir/$(basename "$artifact")"
  cp "$artifact" "$destination"
  (
    cd "$signed_dir"
    sha256sum "$(basename "$destination")"
  ) > "$destination.sha256"
  printf '%s' "$RELEASE_GPG_PASSPHRASE" |
    gpg --batch --yes --armor --detach-sign \
      --pinentry-mode loopback \
      --passphrase-fd 0 \
      --local-user "$RELEASE_GPG_FINGERPRINT!" \
      --output "$destination.asc" \
      "$destination"
  verification_status="$(
    gpg --batch --status-fd 1 --verify "$destination.asc" "$destination" 2>/dev/null
  )" || die "Detached signature verification failed for $(basename "$destination")"
  verified_fingerprint="$(
    awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" { print $3; exit }' \
      <<<"$verification_status"
  )"
  [[ "$verified_fingerprint" == "$RELEASE_GPG_FINGERPRINT" ]] ||
    die "Signature was not produced by the configured release key"
done

find "$signed_dir" -maxdepth 1 -type f -print
