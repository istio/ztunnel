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

use std::time::{Instant, SystemTime};

#[derive(Clone)]
pub struct Converter {
    now: Instant,
    sys_now: SystemTime,
}

impl Converter {
    pub fn new() -> Self {
        Self::new_at(SystemTime::now())
    }

    pub fn new_at(sys_now: SystemTime) -> Self {
        Self {
            sys_now,
            now: Instant::now(),
        }
    }

    pub fn system_time_to_instant(&self, t: SystemTime) -> Option<Instant> {
        match t.duration_since(self.sys_now) {
            Ok(d) => Some(self.now + d),
            Err(_) => match self.sys_now.duration_since(t) {
                Ok(d) => self.now.checked_sub(d),
                Err(_) => panic!("time both before and after"),
            },
        }
    }

    pub fn instant_to_system_time(&self, t: Instant) -> Option<SystemTime> {
        if t > self.now {
            self.sys_now
                .checked_add(t.saturating_duration_since(self.now))
        } else {
            self.sys_now
                .checked_sub(self.now.saturating_duration_since(t))
        }
    }

    pub fn elapsed_nanos(&self, now: Instant) -> u128 {
        now.duration_since(self.now).as_nanos()
    }

    pub fn subsec_nanos(&self) -> u32 {
        self.sys_now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    }
}

impl Default for Converter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    #[test]
    fn test_converter() {
        const DELAY: Duration = Duration::from_secs(1);
        let conv = super::Converter::new();
        let now = Instant::now();
        let sys_now = conv.instant_to_system_time(now).unwrap();
        let later = conv.system_time_to_instant(sys_now + DELAY);
        assert_eq!(later, Some(now + DELAY));
    }
}
