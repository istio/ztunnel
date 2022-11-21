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

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use tokio::io;

use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::net::TcpListener;

pub struct TestServer {
    listener: TcpListener,
}

const BUFFERSIZE: usize = 0x10000; // 64k pipe buffer

impl TestServer {
    pub async fn new() -> TestServer {
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
        let listener = TcpListener::bind(addr).await.unwrap();
        TestServer { listener }
    }

    pub fn address(&self) -> SocketAddr {
        self.listener.local_addr().unwrap()
    }

    pub async fn run(self) {
        loop {
            let (mut socket, _) = self.listener.accept().await.unwrap();

            tokio::spawn(async move {
                let (mut r, mut w) = socket.split();

                // read data from the socket and write the data back.
                copy_tcp(&mut r, &mut w).await.expect("tcp copy");
            });
        }
    }
}

/// copy_tcp splices between two sockets
/// Copied from https://github.com/Soniccube/realm/blob/f8ab5549fc9be1f0237b8721073a7fa83dc630e8/src/zero_copy.rs for now;
/// we should scrutinize the implementation more closely when we use outside of tests
#[cfg(target_os = "linux")]
pub async fn copy_tcp(r: &mut ReadHalf<'_>, w: &mut WriteHalf<'_>) -> io::Result<u64> {
    use libc::{c_int, O_NONBLOCK};
    use std::os::unix::prelude::AsRawFd;
    // create pipe
    let mut pipes = std::mem::MaybeUninit::<[c_int; 2]>::uninit();
    let (rpipe, wpipe) = unsafe {
        if libc::pipe2(pipes.as_mut_ptr() as *mut c_int, O_NONBLOCK) < 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "failed to call pipe"));
        }
        (pipes.assume_init()[0], pipes.assume_init()[1])
    };
    // get raw fd
    let rfd = r.as_ref().as_raw_fd();
    let wfd = w.as_ref().as_raw_fd();
    let mut n: usize = 0;
    let mut total: u64 = 0;
    let mut done = false;

    'LOOP: loop {
        // read until the socket buffer is empty
        // or the pipe is filled
        r.as_ref().readable().await?;
        while n < BUFFERSIZE {
            let x = splice_n(rfd, wpipe, BUFFERSIZE - n);
            match x {
                x if x > 0 => n += x as usize,
                x if x == 0 => {
                    done = true;
                    break;
                }
                x if x < 0 && is_wouldblock() => break,
                _ => break 'LOOP,
            }
        }
        total += n as u64;
        // write until the pipe is empty
        while n > 0 {
            w.as_ref().writable().await?;
            match splice_n(rpipe, wfd, n) {
                x if x > 0 => n -= x as usize,
                x if x < 0 && is_wouldblock() => {
                    // clear readiness (EPOLLOUT)
                    let _ = r.as_ref().try_write(&[0u8; 0]);
                }
                _ => break 'LOOP,
            }
        }
        // complete
        if done {
            break;
        }
        // clear readiness (EPOLLIN)
        let _ = r.as_ref().try_read(&mut [0u8; 0]);
    }

    unsafe {
        libc::close(rpipe);
        libc::close(wpipe);
    }
    Ok(total)
}

#[cfg(not(target_os = "linux"))]
async fn copy_tcp(r: &mut ReadHalf<'_>, w: &mut WriteHalf<'_>) -> io::Result<u64> {
    io::copy(r, w).await
}

#[cfg(target_os = "linux")]
fn splice_n(r: i32, w: i32, n: usize) -> isize {
    use libc::{loff_t, SPLICE_F_MOVE, SPLICE_F_NONBLOCK};
    unsafe {
        libc::splice(
            r,
            std::ptr::null_mut::<loff_t>(),
            w,
            std::ptr::null_mut::<loff_t>(),
            n,
            SPLICE_F_MOVE | SPLICE_F_NONBLOCK,
        )
    }
}

#[cfg(target_os = "linux")]
fn is_wouldblock() -> bool {
    use libc::{EAGAIN, EWOULDBLOCK};
    let errno = unsafe { *libc::__errno_location() };
    errno == EWOULDBLOCK || errno == EAGAIN
}
