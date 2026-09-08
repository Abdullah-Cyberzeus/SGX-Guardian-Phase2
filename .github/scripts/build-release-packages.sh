#!/usr/bin/env bash
set -euo pipefail

die() {
  echo "ERROR: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

version="${1:-}"
binary_path="${2:-}"
output_dir="${3:-}"
source_date_epoch="${4:-}"

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
  die "Version must be a stable semantic version, for example 1.2.3"
[[ -x "$binary_path" ]] || die "Release binary is missing or not executable: $binary_path"
[[ -n "$output_dir" ]] || die "Output directory is required"
[[ "$source_date_epoch" =~ ^[0-9]+$ ]] || die "SOURCE_DATE_EPOCH must be an integer"

for command_name in dpkg-deb rpmbuild tar install sed find; do
  require_command "$command_name"
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
binary_path="$(realpath "$binary_path")"
output_dir="$(realpath -m "$output_dir")"

if [[ -d "$output_dir" ]] && find "$output_dir" -mindepth 1 -print -quit | grep -q .; then
  die "Output directory must be empty: $output_dir"
fi
mkdir -p "$output_dir"

work_dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/guardian-packages.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT

deb_arch="${DEB_ARCH:-amd64}"
deb_root="$work_dir/deb-root"
deb_output="$output_dir/sgx-guardian-client_${version}_${deb_arch}.deb"

install -D -m 0755 "$binary_path" "$deb_root/usr/bin/sgx-guardian"
install -D -m 0644 "$repo_root/packaging/sgx-guardian.service" \
  "$deb_root/lib/systemd/system/sgx-guardian.service"
install -d -m 0755 "$deb_root/etc/sgx-guardian/config"
cp "$repo_root"/packaging/common/config/node*.yaml "$deb_root/etc/sgx-guardian/config/"
install -m 0644 "$repo_root/packaging/common/config/node_profile" \
  "$deb_root/etc/sgx-guardian/node_profile"
install -d -m 0755 "$deb_root/etc/sgx-guardian/policies"
cp -R "$repo_root/packaging/common/policies/." "$deb_root/etc/sgx-guardian/policies/"
cp -R "$repo_root/packaging/deb/DEBIAN" "$deb_root/DEBIAN"
chmod 0755 "$deb_root/DEBIAN" "$deb_root/DEBIAN/postinst" \
  "$deb_root/DEBIAN/postrm" "$deb_root/DEBIAN/prerm"
sed -i -E "s/^Version:.*/Version: ${version}/; s/^Architecture:.*/Architecture: ${deb_arch}/" \
  "$deb_root/DEBIAN/control"
find "$deb_root" -exec touch --date="@$source_date_epoch" {} +
SOURCE_DATE_EPOCH="$source_date_epoch" \
  dpkg-deb --root-owner-group --build "$deb_root" "$deb_output"
[[ -s "$deb_output" ]] || die "Debian package was not generated: $deb_output"

rpm_top="$work_dir/rpmbuild"
rpm_source_name="sgx-guardian-client-${version}"
rpm_source_root="$work_dir/$rpm_source_name"
install -d "$rpm_top/BUILD" "$rpm_top/BUILDROOT" "$rpm_top/RPMS" \
  "$rpm_top/SOURCES" "$rpm_top/SPECS" "$rpm_top/SRPMS"
install -D -m 0755 "$binary_path" "$rpm_source_root/sgx-guardian"
install -D -m 0644 "$repo_root/packaging/sgx-guardian.service" \
  "$rpm_source_root/sgx-guardian.service"
cp -R "$repo_root/packaging/common/config" "$rpm_source_root/config"
cp -R "$repo_root/packaging/common/policies" "$rpm_source_root/policies"
find "$rpm_source_root" -exec touch --date="@$source_date_epoch" {} +
tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner \
  -czf "$rpm_top/SOURCES/$rpm_source_name.tar.gz" \
  -C "$work_dir" "$rpm_source_name"
cp "$repo_root/packaging/rpm/SPECS/sgx-guardian-client.spec" "$rpm_top/SPECS/"

SOURCE_DATE_EPOCH="$source_date_epoch" rpmbuild -bb "$rpm_top/SPECS/sgx-guardian-client.spec" \
  --define "_topdir $rpm_top" \
  --define "_buildhost reproducible" \
  --define "version_override $version" \
  --define "source_date_epoch $source_date_epoch" \
  --define "use_source_date_epoch_as_buildtime 1" \
  --define "clamp_mtime_to_source_date_epoch 1"

mapfile -d '' rpm_outputs < <(find "$rpm_top/RPMS" -type f -name '*.rpm' -print0)
[[ "${#rpm_outputs[@]}" -eq 1 ]] ||
  die "Expected exactly one RPM package, found ${#rpm_outputs[@]}"
cp "${rpm_outputs[0]}" "$output_dir/"

mapfile -d '' package_outputs < <(
  find "$output_dir" -maxdepth 1 -type f \( -name '*.deb' -o -name '*.rpm' \) -print0
)
[[ "${#package_outputs[@]}" -eq 2 ]] ||
  die "Expected one Debian and one RPM package, found ${#package_outputs[@]}"
printf 'Built package: %s\n' "${package_outputs[@]}"
