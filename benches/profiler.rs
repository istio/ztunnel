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

use criterion::profiler::Profiler;
use pprof::ProfilerGuard;
use pprof::protos::Message;

use std::fs::File;
use std::io::Write;
use std::os::raw::c_int;
use std::path::Path;

#[allow(clippy::large_enum_variant)]
pub enum Output {
    Protobuf,
}

pub struct PProfProfiler<'a> {
    frequency: c_int,
    output: Output,
    active_profiler: Option<ProfilerGuard<'a>>,
}

impl<'a> PProfProfiler<'a> {
    pub fn new(frequency: c_int, output: Output) -> Self {
        Self {
            frequency,
            output,
            active_profiler: None,
        }
    }
}

impl<'a> Profiler for PProfProfiler<'a> {
    fn start_profiling(&mut self, _benchmark_id: &str, _benchmark_dir: &Path) {
        self.active_profiler = Some(ProfilerGuard::new(self.frequency).unwrap());
    }

    fn stop_profiling(&mut self, _benchmark_id: &str, benchmark_dir: &Path) {
        std::fs::create_dir_all(benchmark_dir).unwrap();

        let filename = match self.output {
            Output::Protobuf => "profile.pb",
        };
        let output_path = benchmark_dir.join(filename);
        let output_file = File::create(&output_path).unwrap_or_else(|_| {
            panic!("File system error while creating {}", output_path.display())
        });

        if let Some(profiler) = self.active_profiler.take() {
            match &mut self.output {
                Output::Protobuf => {
                    let mut output_file = output_file;

                    let profile = profiler.report().build().unwrap().pprof().unwrap();

                    let mut content = Vec::new();
                    profile
                        .write_to_vec(&mut content)
                        .expect("Error while encoding protobuf");

                    output_file
                        .write_all(&content)
                        .expect("Error while writing protobuf");
                }
            }
        }
    }
}
