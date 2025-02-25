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

use hyper::{HeaderMap, http::HeaderValue};
use libfuzzer_sys::fuzz_target;
use ztunnel::baggage::parse_baggage_header;
use ztunnel::proxy::BAGGAGE_HEADER;

fuzz_target!(|data: &[u8]| {
    let _ = run_baggage_header_parser(data);
    let _ = run_forwarded_header_parser(data);
});

fn run_baggage_header_parser(data: &[u8]) -> anyhow::Result<()> {
    let mut hm = HeaderMap::new();
    hm.append(BAGGAGE_HEADER, HeaderValue::from_bytes(data)?);
    parse_baggage_header(hm.get_all(BAGGAGE_HEADER))?;
    Ok(())
}

fn run_forwarded_header_parser(data: &[u8]) -> anyhow::Result<()> {
    let s = std::str::from_utf8(data)?;
    let _ = ztunnel::proxy::parse_forwarded_host(s);
    Ok(())
}
