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

// Ported from agentgateway (https://github.com/agentgateway/agentgateway),
// derived from tracing-appender (Copyright (c) 2019 Tokio Contributors, MIT
// license). The worker drains the channel and coalesces up to GROUP_SIZE
// lines into a single writev(2).
use std::fmt::Debug;
use std::io::{IoSlice, Write};
use std::thread;

use crossbeam_channel::{Receiver, RecvError, TryRecvError};

use super::msg::Msg;

pub(crate) struct Worker<T: Write + Send + 'static> {
    writer: T,
    receiver: Receiver<Msg>,
    shutdown: Receiver<()>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum WorkerState {
    Disconnected,
    Shutdown,
    Error,
}

impl<T: Write + Send + 'static> Worker<T> {
    pub(crate) fn new(receiver: Receiver<Msg>, writer: T, shutdown: Receiver<()>) -> Worker<T> {
        Self {
            writer,
            receiver,
            shutdown,
        }
    }

    #[inline]
    fn handle_recv(&mut self, result: Result<Msg, RecvError>) -> Result<Vec<u8>, WorkerState> {
        match result {
            Ok(Msg::Line(msg)) => Ok(msg),
            Ok(Msg::Shutdown) => Err(WorkerState::Shutdown),
            Err(_) => Err(WorkerState::Disconnected),
        }
    }

    fn handle_try_recv(
        &mut self,
        result: Result<Msg, TryRecvError>,
    ) -> Result<Option<Vec<u8>>, WorkerState> {
        match result {
            Ok(Msg::Line(msg)) => Ok(Some(msg)),
            Err(TryRecvError::Empty) => Ok(None),
            Ok(Msg::Shutdown) => Err(WorkerState::Shutdown),
            Err(TryRecvError::Disconnected) => Err(WorkerState::Disconnected),
        }
    }

    /// Blocks on the first recv of each batch of logs, unless the
    /// channel is disconnected. Afterwards, grabs as many logs as
    /// it can off the channel, buffers them and attempts a flush.
    pub(crate) fn work(&mut self, mut buf: VectoredIOHelperInstance) -> Result<(), WorkerState> {
        // At high throughputs, we have more incoming messages than we can write out
        // So we batch up big batches of writes to collapse into a single syscall
        let msg = self.handle_recv(self.receiver.recv())?;
        buf.push(msg);
        let mut res = Ok(());
        while buf.can_push() {
            let try_recv_result = self.receiver.try_recv();
            match self.handle_try_recv(try_recv_result) {
                Ok(Some(msg)) => {
                    buf.push(msg);
                }
                Ok(None) => break,
                Err(e) => res = Err(e),
            }
        }

        buf.flush(&mut self.writer)
            .map_err(|_| WorkerState::Error)?;
        res
    }

    /// Creates a worker thread that processes a channel until it's disconnected
    pub(crate) fn worker_thread(mut self, name: String) -> std::thread::JoinHandle<()> {
        thread::Builder::new()
            .name(name)
            .spawn(move || {
                let mut buf = VectoredIOHelper::new();
                loop {
                    match self.work(buf.instance()) {
                        Ok(()) => {}
                        Err(WorkerState::Shutdown) | Err(WorkerState::Disconnected) => {
                            let _ = self.shutdown.recv();
                            break;
                        }
                        Err(WorkerState::Error) => {
                            // TODO: Expose a metric for IO Errors, or print to stderr
                        }
                    }
                }
                if let Err(e) = self.writer.flush() {
                    eprintln!("Failed to flush. Error: {e}");
                }
            })
            .expect("failed to spawn `tracing-appender` non-blocking worker thread")
    }
}

// Nightly (https://github.com/rust-lang/rust/issues/70436)
fn write_all_vectored<T: Write>(
    file: &mut T,
    mut bufs: &mut [IoSlice<'_>],
) -> std::io::Result<usize> {
    // Guarantee that bufs is empty if it contains no data,
    // to avoid calling write_vectored if there is no data to be written.
    IoSlice::advance_slices(&mut bufs, 0);
    let mut total = 0;
    while !bufs.is_empty() {
        match file.write_vectored(bufs) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write whole buffer",
                ));
            }
            Ok(n) => {
                total += n;
                IoSlice::advance_slices(&mut bufs, n)
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

const GROUP_SIZE: usize = 64;

pub(crate) struct VectoredIOHelper {
    bytes_buffer: Vec<Vec<u8>>,
}

impl VectoredIOHelper {
    pub fn new() -> Self {
        VectoredIOHelper {
            bytes_buffer: Vec::with_capacity(GROUP_SIZE),
        }
    }
    pub fn instance(&mut self) -> VectoredIOHelperInstance<'_> {
        self.bytes_buffer.clear();
        VectoredIOHelperInstance {
            bytes_buffer: &mut self.bytes_buffer,
        }
    }
}

pub(crate) struct VectoredIOHelperInstance<'a> {
    bytes_buffer: &'a mut Vec<Vec<u8>>,
}

impl<'a> VectoredIOHelperInstance<'a> {
    pub fn can_push(&mut self) -> bool {
        self.bytes_buffer.len() < self.bytes_buffer.capacity()
    }
    pub fn flush<T: Write>(&mut self, io: &mut T) -> std::io::Result<usize> {
        let mut iovs: [IoSlice; 64] = [IoSlice::new(&[]); GROUP_SIZE];
        for (i, b) in self.bytes_buffer.iter().enumerate() {
            iovs[i] = IoSlice::new(&b[..]);
        }
        let n = write_all_vectored(io, &mut iovs)?;
        io.flush()?;
        Ok(n)
    }
    pub fn push(&mut self, bytes: Vec<u8>) {
        self.bytes_buffer.push(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Writer that accepts at most `cap` bytes per call, to exercise the
    // partial-write advance path in write_all_vectored.
    struct CappedWriter {
        data: Vec<u8>,
        cap: usize,
    }
    impl Write for CappedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let n = buf.len().min(self.cap);
            self.data.extend_from_slice(&buf[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn write_all_vectored_handles_partial_writes() {
        let parts: [&[u8]; 4] = [b"hello ", b"vectored ", b"world\n", b"second\n"];
        let expected: Vec<u8> = parts.concat();
        for cap in [1usize, 3, 7, 1024] {
            let mut w = CappedWriter {
                data: Vec::new(),
                cap,
            };
            let mut iovs: Vec<IoSlice> = parts.iter().map(|p| IoSlice::new(p)).collect();
            let n = write_all_vectored(&mut w, &mut iovs).unwrap();
            assert_eq!(n, expected.len());
            assert_eq!(w.data, expected, "cap={cap}");
        }
    }
}
