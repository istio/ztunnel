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

use hickory_proto::rr::Record;
use hickory_resolver::lookup::Lookup;
use hickory_server::server::Request;
use hickory_server::zone_handler::LookupError;
use std::slice::Iter;

/// Similar to a TrustDNS `Authority`, although the resulting [Answer] indicates whether
/// the response is authoritative. This makes the interface generally more composable and
/// better supports a proxy use case, where some responses may be authoritative and others
/// may not.
#[async_trait::async_trait]
pub trait Resolver: Sync + Send {
    async fn lookup(&self, request: &Request) -> Result<Response, LookupError>;
}

/// Answer returned by a [Resolver].
#[derive(Debug)]
pub struct Response {
    answers: Vec<Record>,
    additionals: Vec<Record>,
    is_authoritative: bool,
}

impl Response {
    pub fn new(answers: Vec<Record>, additionals: Vec<Record>, is_authoritative: bool) -> Self {
        Self {
            answers,
            additionals,
            is_authoritative,
        }
    }

    /// Returns an iterator over the records returned by the [Resolver].
    pub fn answers(&self) -> RecordIter<'_> {
        RecordIter(self.answers.iter())
    }

    pub fn additionals(&self) -> RecordIter<'_> {
        RecordIter(self.additionals.iter())
    }

    /// Indicates whether the [Resolver] is the authority for the returned records.
    pub fn is_authoritative(&self) -> bool {
        self.is_authoritative
    }
}

impl From<Lookup> for Response {
    fn from(value: Lookup) -> Self {
        Self {
            answers: value.answers().to_vec(),
            additionals: value.additionals().to_vec(),
            is_authoritative: false, // Non-authoritative, since results came from upstream resolver.
        }
    }
}

/// Borrowed view of set of [`Record`]s returned from an [Answer].
pub struct RecordIter<'a>(Iter<'a, Record>);

impl<'a> Iterator for RecordIter<'a> {
    type Item = &'a Record;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}
