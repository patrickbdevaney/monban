//! STEK hand-over by pipe only (UP-5): a u32 big-endian length prefix followed by one F11 `stek` frame, written to
//! a FIFO inside the 0700 handover directory. Keys never travel over the handover socket, argv or the environment.

use crate::wire::{self, MAX_FRAME, Msg, STEK_KEY_LEN, StekKey};
use std::io::{self, Read, Write};

/// Session-ticket key ring. `Debug` never prints keys.
#[derive(Clone, PartialEq, Eq)]
pub struct StekRing {
    /// Epoch, incremented on every rotation.
    pub epoch: u64,
    /// 1..=4 keys, newest first.
    pub keys: Vec<StekKey>,
}

impl std::fmt::Debug for StekRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StekRing {{ epoch: {}, keys: {} x <redacted> }}", self.epoch, self.keys.len())
    }
}

impl StekRing {
    /// One fresh key from the kernel CSPRNG.
    pub fn generate() -> io::Result<Self> {
        let mut k = [0u8; STEK_KEY_LEN];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut k)?;
        Ok(Self { epoch: 1, keys: vec![StekKey(k)] })
    }
}

/// Write the ring as one length-prefixed frame.
pub fn write_frame(w: &mut impl Write, ring: &StekRing) -> io::Result<()> {
    let body = wire::encode(&Msg::Stek { epoch: ring.epoch, keys: ring.keys.clone() })
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let len = u32::try_from(body.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

/// Read one length-prefixed frame (length capped at [`MAX_FRAME`] before allocating).
pub fn read_frame(r: &mut impl Read) -> io::Result<StekRing> {
    let mut lb = [0u8; 4];
    r.read_exact(&mut lb)?;
    let len = u32::from_be_bytes(lb) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "stek frame too long"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    match wire::decode(&body) {
        Ok(Msg::Stek { epoch, keys }) => Ok(StekRing { epoch, keys }),
        Ok(_) => Err(io::Error::new(io::ErrorKind::InvalidData, "not a stek frame")),
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_caps() {
        let Ok(r) = StekRing::generate() else { return };
        assert!(format!("{r:?}").contains("redacted"));
        let mut buf = Vec::new();
        assert!(write_frame(&mut buf, &r).is_ok());
        assert_eq!(read_frame(&mut buf.as_slice()).ok(), Some(r));
        let huge = (MAX_FRAME as u32 + 1).to_be_bytes();
        assert!(read_frame(&mut huge.as_slice()).is_err());
        let mut wrong = Vec::new();
        let b = wire::encode(&Msg::Done { forced_closes: 0 }).unwrap_or_default();
        wrong.extend_from_slice(&(b.len() as u32).to_be_bytes());
        wrong.extend_from_slice(&b);
        assert!(read_frame(&mut wrong.as_slice()).is_err());
    }
}
