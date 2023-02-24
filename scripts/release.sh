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
    x86_64)
      export ARCH=amd64;;
    aarch64)
      export ARCH=arm64
      # TODO(https://github.com/istio/ztunnel/issues/357) clean up this hack
      sed -i 's/x86_64/arm64/g' .cargo/config.toml
      ;;
    *) echo "unsupported architecture"; exit 1 ;;
esac

cargo build --release

SHA="$(git rev-parse --verify HEAD)"
RELEASE_NAME="ztunnel-${SHA}-${ARCH}"
ls -lh "${WD}/../out/rust/release/ztunnel"
DEST="${DEST:-gs://istio-build/ztunnel}"
if [[ "$CI" == "" ]]; then
  echo "Outside of CI, DEST must be explicitly set"
  exit 1
fi
gsutil cp "${WD}/../out/rust/release/ztunnel" "${DEST}/${RELEASE_NAME}"
