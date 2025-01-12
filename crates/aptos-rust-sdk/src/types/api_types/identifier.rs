use std::fmt;
use std::fmt::{Debug, Formatter};
use std::str::FromStr;

#[derive(Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct Identifier(Box<str>);

impl FromStr for Identifier {
    type Err = anyhow::Error;

    fn from_str(data: &str) -> anyhow::Result<Self> {
        Self::new(data)
    }
}

impl Debug for Identifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self.0)
    }
}
