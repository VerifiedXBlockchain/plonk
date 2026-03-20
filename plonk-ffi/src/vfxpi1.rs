//! VerifiedX `PlonkPublicInputsV1` wire format (must match `ReserveBlockCore/Privacy/PlonkPublicInputsV1.cs`).

pub const MAGIC: &[u8] = b"VFXPI1";
pub const VERSION: u8 = 1;

/// Header: magic (6) + version (1) + circuit (1) = 8 bytes.
pub const HEADER_LEN: usize = 8;

/// Circuit byte (matches `PlonkCircuitType` in C#).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Circuit {
    Transfer = 0,
    Shield = 1,
    Unshield = 2,
    Fee = 3,
}

impl Circuit {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Circuit::Transfer),
            1 => Some(Circuit::Shield),
            2 => Some(Circuit::Unshield),
            3 => Some(Circuit::Fee),
            _ => None,
        }
    }

    /// Total `public_inputs` length for this circuit (v1).
    pub fn total_len(self) -> usize {
        match self {
            Circuit::Transfer => 240,
            Circuit::Shield => 128,
            Circuit::Unshield => 200,
            Circuit::Fee => 160,
        }
    }
}

/// Parsed header + validated full length.
pub fn parse_public_inputs(data: &[u8]) -> Result<Circuit, ()> {
    if data.len() < HEADER_LEN {
        return Err(());
    }
    if &data[0..MAGIC.len()] != MAGIC {
        return Err(());
    }
    if data[MAGIC.len()] != VERSION {
        return Err(());
    }
    let circuit_byte = data[MAGIC.len() + 1];
    let c = Circuit::from_byte(circuit_byte).ok_or(())?;
    if data.len() != c.total_len() {
        return Err(());
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_match_csharp_layout() {
        assert_eq!(Circuit::Transfer.total_len(), 8 + 32 + 32 + 8 + 64 + 96);
        assert_eq!(Circuit::Shield.total_len(), 8 + 32 + 32 + 8 + 48);
        assert_eq!(Circuit::Unshield.total_len(), 8 + 32 + 32 + 8 + 8 + 64 + 48);
        assert_eq!(Circuit::Fee.total_len(), 8 + 32 + 32 + 8 + 32 + 48);
    }

    #[test]
    fn parse_minimal_transfer() {
        let mut v = vec![0u8; Circuit::Transfer.total_len()];
        v[0..6].copy_from_slice(MAGIC);
        v[6] = VERSION;
        v[7] = Circuit::Transfer as u8;
        assert_eq!(parse_public_inputs(&v).unwrap(), Circuit::Transfer);
    }
}
