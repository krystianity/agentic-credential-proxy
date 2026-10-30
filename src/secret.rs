use std::fmt;

/// A credential. Neither `Debug` nor `Display` will print the contents, so a
/// secret cannot reach a log line through `{:?}` or an error context chain.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Self {
        Secret(value)
    }

    /// The only way out. Call it at the point of use, never to store a copy.
    pub fn expose(&self) -> &str {
        &self.0
    }

}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_prints_contents() {
        let s = Secret::new("hunter2".to_string());
        assert_eq!(format!("{s:?}"), "<redacted>");
        assert_eq!(format!("{s}"), "<redacted>");
        assert!(!format!("{s:?} {s}").contains("hunter2"));
    }
}
