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

use std::{cmp, io};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tracing::info;

/// run_client_throughput reads and writes as much data as possible as fast as possible, until `target`
/// bytes are read+written.
pub async fn run_throughput(stream: &mut TcpStream, target: usize) -> Result<(), io::Error> {
    let start = Instant::now();
    let (mut r, mut w) = stream.split();
    let writer = async move {
        let mut wrote = 0;
        let buffer = vec![0; 200 * 1024 * 1024];
        while wrote < target {
            let length = cmp::min(buffer.len(), target - wrote);
            wrote += w.write(&buffer[..length]).await?;
        }
        Ok::<usize, io::Error>(wrote)
    };
    let reader = async move {
        let mut read = 0;
        let mut buffer = vec![0; 200 * 1024 * 1024];
        while read < target {
            let length = cmp::min(buffer.len(), target - read);
            read += r.read(&mut buffer[..length]).await?;
        }
        Ok::<usize, io::Error>(read)
    };
    let (wrote, _read) = tokio::try_join!(writer, reader)?;
    let elapsed = start.elapsed().as_micros() as f64 / 1_000_000.0;
    let throughput = wrote as f64 / elapsed / 0.125e9;
    info!(
        "throughput: {:.3} Gb/s, wrote {wrote} in {:?}",
        throughput,
        start.elapsed()
    );
    Ok(())
}

pub async fn run_latency(stream: &mut TcpStream, amt: usize) -> Result<(), io::Error> {
    let start = Instant::now();
    let (mut r, mut w) = stream.split();
    let mut buffer = vec![0; amt];
    w.write_all(&buffer).await?;
    r.read_exact(&mut buffer).await?;
    info!("latency: wrote {amt} in {:?}", start.elapsed());
    Ok(())
}

/// run_auto auto runs latency or throughput mode automatically based on the input size
/// large inputs use the throughput mode
pub async fn run_auto(stream: &mut TcpStream, amt: usize) -> Result<(), io::Error> {
    if amt > 1024 {
        run_throughput(stream, amt).await
    } else {
        run_latency(stream, amt).await
    }
}
