#!/usr/bin/env bash
set -euo pipefail

# Workers Builds provides Node.js; install the Flutter and Rust build tools.
toolchain_dir="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/canokey-build-tools"
flutter_version="3.47.2"
mkdir -p "$toolchain_dir"

if ! command -v flutter >/dev/null 2>&1; then
  if [ ! -d "$toolchain_dir/flutter/.git" ]; then
    git clone --depth 1 --branch "$flutter_version" \
      https://github.com/flutter/flutter.git "$toolchain_dir/flutter"
  fi
  export PATH="$toolchain_dir/flutter/bin:$PATH"
fi

export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
if ! command -v rustup >/dev/null 2>&1; then
  curl --fail --show-error --silent --location https://sh.rustup.rs \
    --output "$toolchain_dir/rustup-init.sh"
  sh "$toolchain_dir/rustup-init.sh" -y --profile minimal --default-toolchain stable
fi
rustup toolchain install stable --profile minimal
export RUSTUP_TOOLCHAIN=stable
rustup target add wasm32-unknown-unknown

flutter config --no-analytics
npm run build
