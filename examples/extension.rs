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

use tracing::info;
use ztunnel::extensions::{Extension, ListenerType};

struct ExampleExtension;

impl ExampleExtension {
    fn new() -> Self {
        Self {}
    }
}

impl Extension for ExampleExtension {
    fn on_listen(&self, l: &tokio::net::TcpListener, _: ListenerType) {
        info!("ExampleExtension: Listening on {}", l.local_addr().unwrap());
    }
}

fn main() -> anyhow::Result<()> {
    ztunnel::entry(Some(Box::new(ExampleExtension::new())))
}
