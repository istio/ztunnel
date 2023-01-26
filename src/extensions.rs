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

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamDestination {
    Ztunnel,
    UpstreamServer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerType {
    Outbound,
    InboundPassthrough,
}

/// This allows extending the data plane with custom logic. For example, setting custom
/// socket options.
pub trait Extension {
    /// The name of the extension. Used for the Debug impl.
    fn name(&self) -> &'static str {
        std::any::type_name::<Self>()
    }
    /// Called when the the output,inbound and inbound passthrough
    ///  listeners are /established.
    fn on_listen(&self, _: &TcpListener, _: ListenerType) {}
    /// Called when a new connection is accepted by and of the above listeners.
    fn on_accept(&self, _: &TcpStream, _: ListenerType) {}
    /// Called before connecting to an upstream server or another ztunnel.
    /// at this point the socket is not connected.
    fn on_pre_connect(&self, _: &TcpSocket, _: UpstreamDestination) {}
    /// Called when a connection to an upstream server or another ztunnel done and about to be
    /// closed. Note that on the case of a connection failure, this will not be called.
    fn on_connection_done(&self, _: &TcpStream) {}
}

impl std::fmt::Debug for dyn Extension + Sync + Send {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Extension")
            .field("name", &self.name())
            .finish()
    }
}

impl serde::Serialize for dyn Extension + Sync + Send {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.name())
    }
}

#[derive(serde::Serialize, Clone, Debug)]
pub struct ExtensionManager {
    extensions: Option<std::sync::Arc<dyn Extension + Sync + Send>>,
}

impl ExtensionManager {
    pub fn new(ext: Option<Box<dyn Extension + Sync + Send>>) -> Self {
        ExtensionManager {
            extensions: ext.map(|e| e.into()),
        }
    }

    fn on_listen(&self, l: &TcpListener, t: ListenerType) {
        if let Some(ext) = self.extensions.as_ref() {
            ext.on_listen(l, t);
        }
    }

    // Bind a listener.
    pub async fn bind(
        &self,
        a: std::net::SocketAddr,
        t: ListenerType,
    ) -> std::io::Result<WrappedTcpListener> {
        let inner = TcpListener::bind(a).await;
        inner.map(|l| {
            self.on_listen(&l, t);
            WrappedTcpListener {
                inner: l,
                ext: self.extensions.clone(),
                listener_type: t,
            }
        })
    }

    /// Connect to an upstream server.
    pub async fn connect(
        &self,
        local: Option<std::net::IpAddr>,
        addr: std::net::SocketAddr,
        dest: UpstreamDestination,
    ) -> std::io::Result<WrappedStream> {
        let socket = if addr.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };

        if let Some(ext) = self.extensions.as_ref() {
            ext.on_pre_connect(&socket, dest);
        }

        super::proxy::freebind_connect(socket, local, addr)
            .await
            .map(|s| self.wrap_stream(s))
    }

    // Wraps a stream such that on_connection_done is called when the stream is dropped.
    fn wrap_stream(&self, s: TcpStream) -> WrappedStream {
        WrappedStream {
            inner: s,
            ext: self.extensions.clone(),
        }
    }
}

pub struct WrappedTcpListener {
    inner: TcpListener,
    ext: Option<std::sync::Arc<dyn Extension + Sync + Send>>,
    listener_type: ListenerType,
}

impl WrappedTcpListener {
    pub async fn accept(&self) -> std::io::Result<(TcpStream, std::net::SocketAddr)> {
        let ret = self.inner.accept().await;
        if let Ok((s, _)) = &ret {
            if let Some(ext) = &self.ext {
                ext.on_accept(s, self.listener_type);
            }
        }
        ret
    }
}

impl AsMut<TcpListener> for WrappedTcpListener {
    fn as_mut(&mut self) -> &mut TcpListener {
        &mut self.inner
    }
}

impl AsRef<TcpListener> for WrappedTcpListener {
    fn as_ref(&self) -> &TcpListener {
        &self.inner
    }
}

#[derive(Debug)]
pub struct WrappedStream {
    inner: TcpStream,
    ext: Option<std::sync::Arc<dyn Extension + Sync + Send>>,
}

impl WrappedStream {
    fn pin_get_inner(self: std::pin::Pin<&mut Self>) -> std::pin::Pin<&mut TcpStream> {
        // This is okay because `inner` is pinned when `self` is.
        unsafe { self.map_unchecked_mut(|s| &mut s.inner) }
    }
}

// Some functions (e.g. TLS) need to own the stream. so we impl these wrappers so they can own this
// stream.

impl AsyncRead for WrappedStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.pin_get_inner().poll_read(cx, buf)
    }
}

impl AsyncWrite for WrappedStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.pin_get_inner().poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.pin_get_inner().poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.pin_get_inner().poll_shutdown(cx)
    }
}

impl AsMut<TcpStream> for WrappedStream {
    fn as_mut(&mut self) -> &mut TcpStream {
        &mut self.inner
    }
}

impl AsRef<TcpStream> for WrappedStream {
    fn as_ref(&self) -> &TcpStream {
        &self.inner
    }
}

impl Drop for WrappedStream {
    fn drop(&mut self) {
        // see https://doc.rust-lang.org/std/pin/index.html#drop-implementation for details
        inner_drop(unsafe { std::pin::Pin::new_unchecked(self) });
        fn inner_drop(this: std::pin::Pin<&mut WrappedStream>) {
            // Actual drop code goes here.
            if let Some(ext) = this.ext.as_ref() {
                ext.on_connection_done(&this.inner);
            }
        }
    }
}

#[cfg(test)]
pub mod mock {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[derive(Debug, Default)]
    pub struct MockExtensionState {
        pub on_accept: AtomicUsize,
        pub on_listen: AtomicUsize,
        pub on_pre_connect: AtomicUsize,
        pub on_pre_connect_args: std::sync::Mutex<Vec<UpstreamDestination>>,
        pub on_connection_done: AtomicUsize,
    }

    #[derive(Debug, Default)]
    pub struct MockExtension {
        pub state: Arc<MockExtensionState>,
    }

    impl Extension for MockExtension {
        fn on_listen(&self, _l: &TcpListener, _t: ListenerType) {
            self.state.on_listen.fetch_add(1, Ordering::SeqCst);
        }

        fn on_accept(&self, _s: &TcpStream, _t: ListenerType) {
            self.state.on_accept.fetch_add(1, Ordering::SeqCst);
        }

        fn on_pre_connect(&self, s: &TcpSocket, d: UpstreamDestination) {
            let socket_ref = socket2::SockRef::from(s);
            socket_ref
                .set_keepalive(true)
                .expect("failed to set keepalive");
            self.state.on_pre_connect.fetch_add(1, Ordering::SeqCst);
            self.state.on_pre_connect_args.lock().unwrap().push(d);
        }

        fn on_connection_done(&self, _s: &TcpStream) {
            self.state.on_connection_done.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::*;
    use super::*;

    use std::sync::atomic::Ordering;
    #[tokio::test]
    async fn test_extension_manager() {
        // we place these here to avoid warnings about unused imports
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let ext: MockExtension = Default::default();
        let state = ext.state.clone();

        let ext: Box<dyn Extension + Sync + Send> = Box::new(ext);
        let ext = Some(ext);
        let ext = ExtensionManager::new(ext);
        let sa = "127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap();

        let listener = ext.bind(sa, ListenerType::Outbound).await.unwrap();
        assert_eq!(state.on_listen.load(Ordering::SeqCst), 1);

        let local_address = listener.as_ref().local_addr().unwrap();

        let cloned_state = state.clone();
        tokio::spawn(async move {
            // connect to server
            let _ = tokio::time::timeout(std::time::Duration::from_secs(1), async {
                let mut conn = ext
                    .connect(None, local_address, UpstreamDestination::UpstreamServer)
                    .await
                    .unwrap();
                assert_eq!(cloned_state.on_pre_connect.load(Ordering::SeqCst), 1);

                let socket_ref = socket2::SockRef::from(conn.as_ref());
                let keep_alive = socket_ref.keepalive().expect("failed to read keepalive");
                assert_eq!(keep_alive, true);
                // read/write some bytes to verify we wrapped correctly
                let mut buf = [0u8; 3];

                let _ = conn.read(&mut buf).await.unwrap();
                assert_eq!([1, 2, 3], buf);
                let _ = conn.write(&buf).await.unwrap();
                let _ = conn.flush().await.unwrap();

                std::mem::drop(conn);
                assert_eq!(cloned_state.on_connection_done.load(Ordering::SeqCst), 1);
            })
            .await
            .unwrap();
        });

        // receive connection
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let (mut conn, _) = listener.accept().await.unwrap();
            assert_eq!(state.on_accept.load(Ordering::SeqCst), 1);
            let mut buf = [1u8, 2, 3];

            let _ = conn.write(&buf).await.unwrap();
            let _ = conn.read(&mut buf).await.unwrap();
            assert_eq!([1, 2, 3], buf);
        })
        .await
        .unwrap();
    }
}
