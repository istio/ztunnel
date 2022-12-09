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

use std::io;

use hyper::server::conn::AddrIncoming;

use tokio::net::{TcpListener, TcpStream};
use tokio_stream::{Stream, StreamExt};
use tracing::{debug, warn};

use crate::tls::{BoringTlsAcceptor, CertProvider, TlsError};
pub fn tls_server<T: CertProvider + Clone + 'static>(
    acceptor: T,
    listener: TcpListener,
) -> impl Stream<
    Item = Result<tokio_boring::SslStream<TcpStream>, tls_listener::Error<io::Error, TlsError>>,
> {
    let boring_acceptor = BoringTlsAcceptor { acceptor };
    let mut listener = AddrIncoming::from_listener(listener).expect("server bind");
    listener.set_nodelay(true);

    tls_listener::builder(boring_acceptor)
        .listen(listener)
        .filter(|conn| {
            // Avoid 'By default, if a client fails the TLS handshake, that is treated as an error, and the TlsListener will return an Err'
            if let Err(err) = conn {
                warn!("TLS handshake error: {}", err);
                false
            } else {
                debug!("TLS handshake succeeded");
                true
            }
        })
}
