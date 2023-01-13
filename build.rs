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

use std::process::Command;

// This build script is used to generate the rust source files that
// we need for XDS GRPC communication.
fn main() -> Result<(), anyhow::Error> {
    let proto_files = vec![
        "proto/xds.proto",
        "proto/workload.proto",
        "proto/authorization.proto",
        "proto/citadel.proto",
    ]
    .iter()
    .map(|name| std::env::current_dir().unwrap().join(name))
    .collect::<Vec<_>>();
    let include_dirs = vec!["proto/"]
        .iter()
        .map(|i| std::env::current_dir().unwrap().join(i))
        .collect::<Vec<_>>();
    let config = {
        let mut c = prost_build::Config::new();
        c.disable_comments(Some("."));
        c.bytes([".istio.workload.Workload", ".istio.security.Address"]);
        c
    };
    tonic_build::configure()
        .build_server(true)
        .compile_with_config(
            config,
            &proto_files
                .iter()
                .map(|path| path.to_str().unwrap())
                .collect::<Vec<_>>(),
            &include_dirs
                .iter()
                .map(|p| p.to_str().unwrap())
                .collect::<Vec<_>>(),
        )?;

    // This tells cargo to re-run this build script only when the proto files
    // we're interested in change or the any of the proto directories were updated.
    for path in vec![proto_files, include_dirs].concat() {
        println!("cargo:rerun-if-changed={}", path.to_str().unwrap());
    }

    match Command::new("common/scripts/report_build_info.sh").output() {
        Ok(output) => {
            for line in String::from_utf8(output.stdout).unwrap().lines() {
                // Each line looks like `istio.io/pkg/version.buildGitRevision=abc`
                if let Some((key, value)) = line.split_once('=') {
                    let key = key.split('.').last().unwrap();
                    println!("cargo:rustc-env=ZTUNNEL_BUILD_{}={}", key, value);
                } else {
                    println!("cargo:warning=invalid build output {}", line);
                }
            }
        }
        Err(err) => {
            println!("cargo:warning={}", err);
        }
    };
    println!(
        "cargo:rustc-env=ZTUNNEL_BUILD_RUSTC_VERSION={}",
        rustc_version::version().unwrap()
    );
    Ok(())
}
