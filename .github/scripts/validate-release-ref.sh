#!/usr/bin/env bash
set -euo pipefail

die() {
  echo "ERROR: $*" >&2
  exit 1
}

release_tag="${1:-}"
release_sha="${2:-}"
main_ref="${3:-origin/main}"
output_file="${4:-}"

[[ "$release_tag" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)$ ]] ||
  die "Release tag must be a stable semantic version such as v1.2.3"
version="${BASH_REMATCH[1]}"
[[ "$release_sha" =~ ^[0-9a-f]{40}$ ]] || die "Release SHA must be a full lowercase commit SHA"
git show-ref --verify --quiet "refs/tags/$release_tag" ||
  die "Release tag is not present in the checkout: $release_tag"

tag_commit="$(git rev-parse "refs/tags/$release_tag^{commit}")"
head_commit="$(git rev-parse HEAD)"
[[ "$tag_commit" == "$release_sha" ]] ||
  die "Release tag $release_tag resolves to $tag_commit, not event SHA $release_sha"
[[ "$head_commit" == "$release_sha" ]] ||
  die "Checked-out commit $head_commit does not match event SHA $release_sha"
git merge-base --is-ancestor "$release_sha" "$main_ref" ||
  die "Release commit $release_sha is not an ancestor of $main_ref"

source_date_epoch="$(git show -s --format=%ct "$release_sha")"
if [[ -n "$output_file" ]]; then
  {
    echo "version=$version"
    echo "commit-sha=$release_sha"
    echo "source-date-epoch=$source_date_epoch"
  } >> "$output_file"
else
  printf 'version=%s\ncommit-sha=%s\nsource-date-epoch=%s\n' \
    "$version" "$release_sha" "$source_date_epoch"
fi
