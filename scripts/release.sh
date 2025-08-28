#!/bin/bash

# Copyright Istio Authors

#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

set -ex

WD=$(dirname "$0")
WD=$(cd "$WD" || exit; pwd)

case $(uname -m) in
  x86_64) export ARCH=amd64;;
  aarch64) export ARCH=arm64 ;;
  *) echo "unsupported architecture"; exit 1;;
esac

if [[ "$TLS_MODE" == "boring" ]]; then
  if [[ "$ARCH" == "arm64" ]]; then
    # TODO(https://github.com/istio/ztunnel/issues/357) clean up this hack
    sed -i 's/x86_64/arm64/g' .cargo/config.toml
  fi
  cargo build --release --no-default-features -F tls-boring
elif [[ "$TLS_MODE" == "aws-lc" ]]; then
  cargo build --release --no-default-features -F tls-aws-lc
elif [[ "$TLS_MODE" == "openssl" ]]; then
  cargo build --release --no-default-features -F tls-openssl
else
  cargo build --release
fi

SHA="$(git rev-parse --verify HEAD)"
BINARY_PREFIX=${BINARY_PREFIX:-"ztunnel"}
RELEASE_NAME="${BINARY_PREFIX}-${SHA}-${ARCH}"
ls -lh "${WD}/../out/rust/release/ztunnel"
DEST="${DEST:-gs://istio-build/ztunnel}"

gsutil cp "${WD}/../out/rust/release/ztunnel" "${DEST}/${RELEASE_NAME}"
