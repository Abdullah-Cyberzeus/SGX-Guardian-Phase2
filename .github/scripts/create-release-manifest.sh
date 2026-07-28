#!/usr/bin/env bash
set -euo pipefail

die() {
  echo "ERROR: $*" >&2
  exit 1
}

package_dir="${1:-}"
manifest_path="${2:-}"
release_tag="${3:-}"
commit_sha="${4:-}"
source_date_epoch="${5:-}"
packaging_image="${6:-}"

[[ -d "$package_dir" ]] || die "Package directory does not exist: $package_dir"
[[ -n "$manifest_path" && ! -e "$manifest_path" ]] ||
  die "Manifest path must be new: $manifest_path"
[[ "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Invalid release tag"
[[ "$commit_sha" =~ ^[0-9a-f]{40}$ ]] || die "Invalid release commit SHA"
[[ "$source_date_epoch" =~ ^[0-9]+$ ]] || die "Invalid source date epoch"
[[ "$packaging_image" =~ @sha256:[0-9a-f]{64}$ ]] ||
  die "Packaging image must be pinned by SHA-256 digest"

mapfile -d '' packages < <(
  find "$package_dir" -maxdepth 1 -type f \( -name '*.deb' -o -name '*.rpm' \) -print0 |
    sort -z
)
[[ "${#packages[@]}" -eq 2 ]] || die "Manifest requires exactly two packages"

first_line() {
  "$@" 2>&1 | sed -n '1{s/\r$//;p;}'
}

{
  echo "manifest_version=1"
  echo "release_tag=$release_tag"
  echo "commit_sha=$commit_sha"
  echo "source_date_epoch=$source_date_epoch"
  echo "packaging_image=$packaging_image"
  echo "rustc_version=$(first_line rustc --version)"
  echo "cargo_version=$(first_line cargo --version)"
  echo "protoc_version=$(first_line protoc --version)"
  echo "dpkg_deb_version=$(first_line dpkg-deb --version)"
  echo "rpmbuild_version=$(first_line rpmbuild --version)"
  echo "gpg_version=$(first_line gpg --version)"
  for package in "${packages[@]}"; do
    digest="$(sha256sum "$package" | awk '{print $1}')"
    echo "package_sha256=$digest  $(basename "$package")"
  done
} > "$manifest_path"
