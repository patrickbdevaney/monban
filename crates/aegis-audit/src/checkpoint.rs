//! c2sp.org/tlog-checkpoint@v1.1.0 note text: origin, tree size (ASCII decimal), root hash (base64), no
//! extension lines.

use crate::encoding::{base64_decode, base64_encode};
use crate::merkle::Hash;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointError {
    BadOrigin,
    Malformed,
}

impl std::fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for CheckpointError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    origin: String,
    size: u64,
    root: Hash,
}

/// Origin: one non-empty line without control characters.
pub fn check_origin(origin: &str) -> Result<(), CheckpointError> {
    if origin.is_empty() || origin.chars().any(char::is_control) { Err(CheckpointError::BadOrigin) } else { Ok(()) }
}

impl Checkpoint {
    pub fn new(origin: &str, size: u64, root: Hash) -> Result<Self, CheckpointError> {
        check_origin(origin)?;
        Ok(Self { origin: origin.to_owned(), size, root })
    }
    pub fn origin(&self) -> &str {
        &self.origin
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn root(&self) -> &Hash {
        &self.root
    }
    /// The note text (signed body), ending in a newline.
    pub fn text(&self) -> String {
        format!("{}\n{}\n{}\n", self.origin, self.size, base64_encode(&self.root))
    }
    /// Parses checkpoint note text (extension lines are rejected: we never write them).
    pub fn parse(text: &str) -> Result<Self, CheckpointError> {
        let body = text.strip_suffix('\n').ok_or(CheckpointError::Malformed)?;
        let mut lines = body.split('\n');
        let (Some(origin), Some(size), Some(root), None) = (lines.next(), lines.next(), lines.next(), lines.next())
        else {
            return Err(CheckpointError::Malformed);
        };
        check_origin(origin)?;
        let canonical = size == "0" || (!size.starts_with('0') && size.bytes().all(|b| b.is_ascii_digit()));
        if size.is_empty() || !canonical {
            return Err(CheckpointError::Malformed);
        }
        let size: u64 = size.parse().map_err(|_| CheckpointError::Malformed)?;
        let raw = base64_decode(root).ok_or(CheckpointError::Malformed)?;
        let root: Hash = raw.as_slice().try_into().map_err(|_| CheckpointError::Malformed)?;
        Ok(Self { origin: origin.to_owned(), size, root })
    }
}

/// A checkpoint and its signed-note serialization (the bytes published at `<prefix>/checkpoint`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCheckpoint {
    pub checkpoint: Checkpoint,
    pub note: String,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn spec_example_parses() {
        let t = "example.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n";
        let c = Checkpoint::parse(t).unwrap();
        assert_eq!(c.size(), 20_852_163);
        assert_eq!(c.text(), t);
        assert!(Checkpoint::parse("o\n01\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n").is_err());
        assert!(Checkpoint::parse("o\n1\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\next\n").is_err());
        assert!(Checkpoint::parse("o\n1\nCsUY\n").is_err());
        assert!(Checkpoint::new("a\nb", 0, [0; 32]).is_err());
    }
}
