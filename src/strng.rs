use std::fmt::Error;
use std::ops::Deref;
use std::rc::Rc;
use std::sync::Arc;
use arcstr::ArcStr;
use prometheus_client::encoding::{EncodeLabelKey, LabelSetEncoder, LabelValueEncoder};

pub type Strng = ArcStr;

pub fn new<A: AsRef<str>>(s: A) -> Strng {
    s.as_ref().into()
}

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
    where T: Into<Strng>{
    fn from(value: T) -> Self {
        RichStrng(value.into())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    fn as_ref_fn<A: AsRef<str>>(s: A) {

    }
    fn string_fn(s: String) {

    }
    fn str_fn(s: &s) {

    }

    #[test]
    fn interning() {
        let a = new("abc");
        let b = new("abc");
        assert_eq!(std::mem::size_of::<Strng>(), 16);
        assert_eq!(format!("{a}"), "abc");
        assert_eq!(a.refcount(), b.refcount());
        assert_eq!(a.refcount(), 2);
        assert_eq!("abc", b.to_string());

        // Compile time assertion we can call function in various ways
        as_ref_fn(new("abc"));
        string_fn(a.to_string());
        as_ref_fn(a.as_ref());
    }
}