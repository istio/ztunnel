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
