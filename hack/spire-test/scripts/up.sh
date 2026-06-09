#!/usr/bin/env bash
# Copyright Istio Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# All-in-one convenience wrapper: builds the SPIRE broker-api images,
# builds the ztunnel image, then runs setup.sh + verify.sh.
#
# Skips work that's already been done (image already present, kind cluster
# already up). Use the individual scripts directly if you need finer control.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

"${SCRIPT_DIR}/build-spire-images.sh"
"${SCRIPT_DIR}/build-ztunnel-image.sh"
"${SCRIPT_DIR}/setup.sh"
"${SCRIPT_DIR}/verify.sh"
