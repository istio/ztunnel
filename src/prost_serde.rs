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

use std::str::FromStr;

use prost_types::Duration;
use serde::Deserialize;
use serde_with::DeserializeAs;

// Duration is a wrapper around prost_types::Duration that adds support for serde deserialization.
pub struct DurationDeserializer;

impl<'de> DeserializeAs<'de, Option<Duration>> for DurationDeserializer {
    fn deserialize_as<D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let dur = Duration::from_str(&s).map_err(serde::de::Error::custom)?;
        Ok(Some(dur))
    }
}
