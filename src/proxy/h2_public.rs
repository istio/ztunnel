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

//! Public interface for HBONE (HTTP/2-based tunneling) functionality
//! 
//! This module provides a stable public API for working with H2 streams
//! and server functionality that is used by the HBONE implementation.
//!
//! The interfaces in this module are designed to be simpler and more
//! stable than the internal implementation details.

use bytes::Bytes;
use h2::{RecvStream, SendStream};
use crate::copy::BufferedSplitter;
use std::future::Future;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_rustls::server::TlsStream;
use http::request::Parts;
use crate::config;
use crate::drain::DrainWatcher;
use crate::proxy::Error;

/// Public H2Stream that represents an HTTP/2 stream with read and write halves
pub struct H2Stream {
    pub read: H2StreamReadHalf,
    pub write: H2StreamWriteHalf,
}

/// Read half of an HTTP/2 stream
pub struct H2StreamReadHalf {
    pub recv_stream: RecvStream,
}

/// Write half of an HTTP/2 stream
pub struct H2StreamWriteHalf {
    pub send_stream: SendStream<Bytes>,
}

// Conversion from private to public types
impl From<crate::proxy::h2::H2Stream> for H2Stream {
    fn from(stream: crate::proxy::h2::H2Stream) -> Self {
        let (read, write) = crate::proxy::h2::H2Stream::split_into_buffered_reader(stream);
        
        let recv_stream = read.into_recv_stream();
        let send_stream = write.into_send_stream();
        
        H2Stream {
            read: H2StreamReadHalf { recv_stream },
            write: H2StreamWriteHalf { send_stream },
        }
    }
}

/// Public interface for H2 server functionality
pub mod server {
    use super::*;
    
    /// Public wrapper for H2Request with simplified interface
    #[derive(Debug)]
    pub struct H2Request {
        inner: crate::proxy::h2::server::H2Request,
    }
    
    impl H2Request {
        /// Get the HTTP request parts
        pub fn get_request(&self) -> &Parts {
            self.inner.get_request()
        }
        
        /// Send an error response
        pub fn send_error(self, resp: http::Response<()>) -> Result<(), Error> {
            self.inner.send_error(resp)
        }
        
        /// Send response and get stream for body
        pub async fn send_response(
            self,
            resp: http::Response<()>,
        ) -> Result<super::H2Stream, Error> {
            self.inner.send_response(resp).await.map(|stream| stream.into())
        }
    }
    
    /// Serve an HTTP/2 connection with handler function
    ///
    /// This is the main entry point for creating an HTTP/2 server
    /// that can handle HBONE (HTTP CONNECT tunneling) requests
    pub async fn serve_connection<F, Fut>(
        cfg: Arc<config::Config>,
        stream: TlsStream<TcpStream>,
        drain: DrainWatcher,
        force_shutdown: watch::Receiver<()>,
        handler: F,
    ) -> Result<(), Error>
    where
        F: Fn(H2Request) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        // Create an adapter function to convert the public H2Request to the private H2Request
        let private_handler = move |req: crate::proxy::h2::server::H2Request| {
            let req = H2Request { inner: req };
            handler(req)
        };
        
        crate::proxy::h2::server::serve_connection(cfg, stream, drain, force_shutdown, private_handler).await
    }
} 