// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_main]

use hyper::http::HeaderValue;
use libfuzzer_sys::fuzz_target;
use ztunnel::baggage::parse_baggage_header;

fuzz_target!(|data: &[u8]| {
    let _ = run_baggage_header_parser(data);
});

fn run_baggage_header_parser(data: &[u8]) -> anyhow::Result<()> {
    let header_value = HeaderValue::from_bytes(data)?;
    parse_baggage_header(Some(&header_value))?;
    Ok(())
}
