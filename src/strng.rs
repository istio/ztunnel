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

use std::fmt::Error;
use std::ops::Deref;

use arcstr::ArcStr;
use prometheus_client::encoding::LabelValueEncoder;

/// 'Strng' provides a string type that has better properties for our use case:
/// * Cheap cloning (ref counting)
/// * Efficient storage (8 bytes vs 24 bytes)
/// * Immutable
/// This is mostly provided by a library, ArcStr, we just provide a very thin wrapper around it
/// for some flexibility.
pub type Strng = ArcStr;

pub fn new<A: AsRef<str>>(s: A) -> Strng {
    Strng::from(s.as_ref())
}

pub use arcstr::format;
pub use arcstr::literal;

/// RichStrng wraps Strng to let us implement arbitrary methods. How annoying.
#[derive(Clone, Hash, Default, Debug, PartialEq, Eq)]
pub struct RichStrng(Strng);

impl prometheus_client::encoding::EncodeLabelValue for RichStrng {
    fn encode(&self, encoder: &mut LabelValueEncoder) -> Result<(), Error> {
        prometheus_client::encoding::EncodeLabelValue::encode(&self.0.as_ref(), encoder)
    }
}

impl Deref for RichStrng {
    type Target = Strng;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> From<T> for RichStrng
where
    T: Into<Strng>,
{
    fn from(value: T) -> Self {
        RichStrng(value.into())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    fn as_ref_fn<A: AsRef<str>>(_s: A) {}
    fn into_string_fn<A: Into<String>>(_s: A) {}
    fn string_fn(_s: String) {}
    fn str_fn(_s: &str) {}

    #[test]
    fn interning() {
        // Mostly we just thinly wrap ArcString, so just validate our assumptions about the library
        let a = new("abc");
        let b = new("abc");
        assert_eq!(std::mem::size_of::<Strng>(), 8);
        assert_eq!(std::format!("{a}"), "abc");
        assert_eq!(super::format!("{a}"), "abc");
        assert_eq!(ArcStr::strong_count(&a), ArcStr::strong_count(&b));
        assert_eq!(ArcStr::strong_count(&a), Some(1));
        let c = a.clone();
        assert_eq!(ArcStr::strong_count(&a), ArcStr::strong_count(&c));
        assert_eq!(ArcStr::strong_count(&a), Some(2));
        assert_eq!("abc", b.to_string());

        // Compile time assertion we can call function in various ways
        as_ref_fn(new("abc"));
        into_string_fn(&*new("abc"));
        string_fn(a.to_string());
        str_fn(&new("abc"));
    }
}
