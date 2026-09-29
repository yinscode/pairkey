#!/bin/bash
set -euo pipefail
experiment_dir="$(cd "$(dirname "$0")" && pwd)"
project_dir="$(cd "$experiment_dir/../.." && pwd)"
source_dir="$project_dir/.local/silence-dkls23/sources"
revision=af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7
archive_sha=e7301fa0886c0232cdf7dad7b2827ef0ce0ea84c1853ea926fe781865d320c9b
mkdir -p "$source_dir"
if [[ ! -f "$source_dir/dkls23.tar.gz" ]]; then
  curl -L --fail --silent --show-error "https://codeload.github.com/silence-laboratories/dkls23/tar.gz/$revision" -o "$source_dir/dkls23.tar.gz"
fi
actual_sha="$(shasum -a 256 "$source_dir/dkls23.tar.gz" | cut -d ' ' -f 1)"
[[ "$actual_sha" == "$archive_sha" ]] || { echo 'Source archive checksum mismatch' >&2; exit 1; }
if [[ ! -d "$source_dir/dkls23-$revision" ]]; then
  tar -xzf "$source_dir/dkls23.tar.gz" -C "$source_dir"
fi
python3 "$experiment_dir/patch-source.py" "$source_dir/dkls23-$revision" "$experiment_dir"
export CARGO_TARGET_DIR="$project_dir/target/silence-dkls23"
[[ $# -gt 0 ]] || { echo 'Usage: bash bootstrap.sh <cargo command> [arguments]' >&2; exit 1; }
exec cargo "$1" --manifest-path "$experiment_dir/Cargo.toml" "${@:2}"
