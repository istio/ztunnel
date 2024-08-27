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

// ZDS uses seqpacket unix sockets to communicate with the node agent.
// It is not implemented in rust, so this provides an implementation for it.

use nix::sys::socket::{
    bind as nixbind, connect as nixconnect, listen, socket, AddressFamily, SockFlag, SockType,
    UnixAddr,
};
use std::cmp;
use std::os::fd::AsRawFd;
use std::path::Path;
use tokio::net::{UnixListener, UnixStream};

pub fn bind(path: &Path) -> std::io::Result<UnixListener> {
    let socket = socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        None,
    )?;

    let addr = UnixAddr::new(path)?;

    nixbind(socket.as_raw_fd(), &addr)?;
    // Do not exceed maximum
    let backlog = cmp::min(1024, libc::SOMAXCONN - 1);
    listen(&socket, nix::sys::socket::Backlog::new(backlog)?)?;

    let std_socket = std::os::unix::net::UnixListener::from(socket);
    UnixListener::from_std(std_socket)
}

pub async fn connect(path: &Path) -> std::io::Result<UnixStream> {
    let socket = socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        None,
    )?;

    let addr = UnixAddr::new(path)?;
    let res = nixconnect(socket.as_raw_fd(), &addr);
    // safe as we just created it, it's non blocking and listening.
    let std_socket = std::os::unix::net::UnixStream::from(socket);
    let socket = UnixStream::from_std(std_socket)?;
    match res {
        Ok(_) => {}
        Err(nix::errno::Errno::EAGAIN) | Err(nix::errno::Errno::EINPROGRESS) => {
            // from the man page:
            //        EAGAIN For nonblocking UNIX domain sockets, the socket is nonblocking, and the connection cannot be completed immediately.
            // doing EINPROGRESS just in case (as that's what mio does).

            // The following is described in the 'man connect':
            //     The socket is nonblocking and the connection cannot be completed immediately. ...
            //     It is possible to select(2) or poll(2) for completion by selecting the socket for writing...
            //     use getsockopt(2) to read the  SO_ERROR option at level SOL_SOCKET to determine
            //     whether connect() completed successfully (SO_ERROR is zero) or unsuccessfully...

            // wait until it is writable (i.e. connect is done)
            socket.writable().await?;
            // connect is done, check for error
            if let Some(e) = socket.take_error()? {
                return Err(e);
            }
        }
        Err(e) => return Err(std::io::Error::from(e)),
    }
    Ok(socket)
}
