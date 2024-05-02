use internment::ArcIntern;

pub type Strng = ArcIntern<str>;

pub fn intern<A: AsRef<str>>(s: A) -> ArcIntern<str> {
    s.as_ref().into()
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn interning() {
        let a = intern("abc");
        let b = intern("abc");
        assert_eq!(std::mem::size_of::<Strng>(), 16);
        assert_eq!(format!("{a}"), "abc");
        assert_eq!(a.refcount(), b.refcount());
        assert_eq!(a.refcount(), 2);
        assert_eq!("abc", b.into_string());
    }
}