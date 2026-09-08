#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/release-package-test.XXXXXX")"
trap 'rm -rf -- "$fixture_dir"' EXIT

fake_bin="$fixture_dir/bin"
mkdir -p "$fake_bin"
printf '#!/usr/bin/env bash\nexit 0\n' > "$fixture_dir/sgx_guardian_client"
chmod +x "$fixture_dir/sgx_guardian_client"

cat > "$fake_bin/dpkg-deb" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--version" ]]; then
  echo "Debian dpkg-deb fixture 1.21.23"
  exit 0
fi
root="${@: -2:1}"
output="${@: -1}"
grep -qx 'Version: 1.2.3' "$root/DEBIAN/control"
grep -qx 'Architecture: amd64' "$root/DEBIAN/control"
test -x "$root/usr/bin/sgx-guardian"
test -f "$root/lib/systemd/system/sgx-guardian.service"
test -f "$root/etc/sgx-guardian/config/nodeA.yaml"
test -f "$root/etc/sgx-guardian/node_profile"
test -f "$root/etc/sgx-guardian/policies/active_policy.yaml"
grep -q 'setcap -r' "$root/DEBIAN/postinst"
grep -q 'setcap -r' "$root/DEBIAN/prerm"
if grep -Eq 'setcap[[:space:]]+cap_' "$root/DEBIAN/postinst" "$root/DEBIAN/prerm"; then
  echo "Debian maintainer scripts grant persistent file capabilities" >&2
  exit 1
fi
printf 'deb fixture' > "$output"
EOF

cat > "$fake_bin/rpmbuild" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--version" ]]; then
  echo "RPM fixture 4.18.0"
  exit 0
fi
top_dir=""
version=""
while (($#)); do
  if [[ "$1" == "--define" ]]; then
    case "$2" in
      "_topdir "*) top_dir="${2#_topdir }" ;;
      "version_override "*) version="${2#version_override }" ;;
    esac
    shift 2
  else
    shift
  fi
done
[[ "$version" == "1.2.3" ]]
tar -tzf "$top_dir/SOURCES/sgx-guardian-client-1.2.3.tar.gz" |
  grep -qx 'sgx-guardian-client-1.2.3/config/nodeA.yaml'
mkdir -p "$top_dir/RPMS/x86_64"
printf 'rpm fixture' > "$top_dir/RPMS/x86_64/sgx-guardian-client-1.2.3-1.x86_64.rpm"
EOF
chmod +x "$fake_bin/dpkg-deb" "$fake_bin/rpmbuild"

PATH="$fake_bin:$PATH" bash "$script_dir/build-release-packages.sh" \
  1.2.3 "$fixture_dir/sgx_guardian_client" "$fixture_dir/dist" 1704067200
[[ "$(find "$fixture_dir/dist" -maxdepth 1 -type f -name '*.deb' | wc -l)" -eq 1 ]]
[[ "$(find "$fixture_dir/dist" -maxdepth 1 -type f -name '*.rpm' | wc -l)" -eq 1 ]]

if PATH="$fake_bin:$PATH" bash "$script_dir/build-release-packages.sh" \
  '1.2.3;false' "$fixture_dir/sgx_guardian_client" "$fixture_dir/invalid" 1704067200 \
  >/dev/null 2>&1; then
  echo "Package builder accepted an unsafe version" >&2
  exit 1
fi

for tool in rustc cargo protoc; do
  cat > "$fake_bin/$tool" <<EOF
#!/usr/bin/env bash
echo "$tool fixture 1.0"
EOF
  chmod +x "$fake_bin/$tool"
done

release_fingerprint="0123456789ABCDEF0123456789ABCDEF01234567"
cat > "$fake_bin/gpg" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
fingerprint="0123456789ABCDEF0123456789ABCDEF01234567"
if [[ "${1:-}" == "--version" ]]; then
  echo "gpg fixture 2.2.40"
  exit 0
fi
if [[ " $* " == *" --list-secret-keys "* ]]; then
  printf 'sec:u:2048:1:0000000000000000:0:0:::::s:::::\n'
  printf 'fpr:::::::::%s:\n' "$fingerprint"
  if [[ "${GPG_TEST_EXTRA_KEY:-0}" == "1" ]]; then
    printf 'sec:u:2048:1:1111111111111111:0:0:::::s:::::\n'
    printf 'fpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:\n'
  fi
  exit 0
fi
if [[ " $* " == *" --verify "* ]]; then
  printf '[GNUPG:] VALIDSIG %s 2026-07-27 0 4 0 1 10 00 %s\n' \
    "$fingerprint" "$fingerprint"
  exit 0
fi
output=""
local_user=""
while (($#)); do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --local-user) local_user="$2"; shift 2 ;;
    *) shift ;;
  esac
done
if [[ -n "$output" ]]; then
  [[ "$local_user" == "$fingerprint!" ]]
  cat >/dev/null
  printf 'signature fixture' > "$output"
fi
EOF
chmod +x "$fake_bin/gpg"

PATH="$fake_bin:$PATH" bash "$script_dir/create-release-manifest.sh" \
  "$fixture_dir/dist" \
  "$fixture_dir/dist/release-manifest.txt" \
  v1.2.3 \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  1704067200 \
  rust@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
grep -qx "package_sha256=.*  sgx-guardian-client_1.2.3_amd64.deb" \
  "$fixture_dir/dist/release-manifest.txt"

PATH="$fake_bin:$PATH" \
  RELEASE_GPG_PRIVATE_KEY='private key fixture' \
  RELEASE_GPG_PASSPHRASE='passphrase fixture' \
  RELEASE_GPG_FINGERPRINT="$release_fingerprint" \
  bash "$script_dir/sign-release-packages.sh" "$fixture_dir/dist" "$fixture_dir/signed"
[[ "$(find "$fixture_dir/signed" -maxdepth 1 -type f | wc -l)" -eq 9 ]]

mkdir "$fixture_dir/missing-rpm"
cp "$fixture_dir/dist/"*.deb "$fixture_dir/missing-rpm/"
cp "$fixture_dir/dist/release-manifest.txt" "$fixture_dir/missing-rpm/"
if PATH="$fake_bin:$PATH" \
  RELEASE_GPG_PRIVATE_KEY='private key fixture' \
  RELEASE_GPG_PASSPHRASE='passphrase fixture' \
  RELEASE_GPG_FINGERPRINT="$release_fingerprint" \
  bash "$script_dir/sign-release-packages.sh" \
    "$fixture_dir/missing-rpm" "$fixture_dir/not-signed" >/dev/null 2>&1; then
  echo "Signer accepted a missing RPM package" >&2
  exit 1
fi

if PATH="$fake_bin:$PATH" \
  RELEASE_GPG_PRIVATE_KEY='private key fixture' \
  RELEASE_GPG_PASSPHRASE='passphrase fixture' \
  RELEASE_GPG_FINGERPRINT='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
  bash "$script_dir/sign-release-packages.sh" \
    "$fixture_dir/dist" "$fixture_dir/wrong-key" >/dev/null 2>&1; then
  echo "Signer accepted a mismatched fingerprint" >&2
  exit 1
fi

if PATH="$fake_bin:$PATH" \
  GPG_TEST_EXTRA_KEY=1 \
  RELEASE_GPG_PRIVATE_KEY='private key fixture' \
  RELEASE_GPG_PASSPHRASE='passphrase fixture' \
  RELEASE_GPG_FINGERPRINT="$release_fingerprint" \
  bash "$script_dir/sign-release-packages.sh" \
    "$fixture_dir/dist" "$fixture_dir/extra-key" >/dev/null 2>&1; then
  echo "Signer accepted more than one primary secret key" >&2
  exit 1
fi

echo "release package helper tests passed"
