//! Shared local macOS RISC0 bounds; these are configuration, not IPC fields.
pub const MAX_GUEST_CYCLES_ENV: &str = "ZKMINER_RISC0_MAX_GUEST_CYCLES";
pub const MIN_SEGMENT_PO2: u8 = 14;
pub const MAX_SEGMENT_PO2: u8 = 21;
pub const DEFAULT_NATIVE_SEGMENT_PO2: u8 = 20;
pub const MAX_GUEST_CYCLES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct Risc0Limits {
    pub max_guest_cycles: u64,
    pub max_segment_po2: u8,
    pub default_segment_po2: u8,
}

impl Risc0Limits {
    pub fn from_environment(native: bool) -> Result<Self, String> {
        match std::env::var(MAX_GUEST_CYCLES_ENV) {
            Ok(value) => Self::parse(Some(&value), native),
            Err(std::env::VarError::NotPresent) => Self::parse(None, native),
            Err(error) => Err(format!("invalid {MAX_GUEST_CYCLES_ENV}: {error}")),
        }
    }

    pub fn parse(value: Option<&str>, native: bool) -> Result<Self, String> {
        let default = if native { MAX_GUEST_CYCLES } else { 4 * 1024 * 1024 };
        let max_guest_cycles = match value {
            Some(value) => value.parse().map_err(|_| format!("invalid {MAX_GUEST_CYCLES_ENV}"))?,
            None => default,
        };
        if !(1..=MAX_GUEST_CYCLES).contains(&max_guest_cycles) {
            return Err(format!("{MAX_GUEST_CYCLES_ENV} must be in 1..={MAX_GUEST_CYCLES}"));
        }
        Ok(Self { max_guest_cycles,
            max_segment_po2: if native { MAX_SEGMENT_PO2 } else { 18 },
            default_segment_po2: if native { DEFAULT_NATIVE_SEGMENT_PO2 } else { 18 },
        })
    }

    pub fn validate_po2(self, po2: Option<u8>) -> Result<(), String> {
        if po2.is_some_and(|n| !(MIN_SEGMENT_PO2..=self.max_segment_po2).contains(&n)) {
            return Err(format!("po2 value out of valid range {MIN_SEGMENT_PO2}..={} for macOS worker", self.max_segment_po2));
        }
        Ok(())
    }

    pub fn validate_guest_cycles(self, cycles: u64) -> Result<(), String> {
        if cycles > self.max_guest_cycles {
            return Err(format!("Session limit exceeded: {cycles} > {} guest cycles", self.max_guest_cycles));
        }
        Ok(())
    }

    /// Claim estimates may be padded total cycles; comparing them to the guest
    /// limit is conservative. Unknown sizes require execution before claiming.
    pub fn validate_claim(self, cycles: u64, po2: Option<u8>) -> Result<(), String> {
        self.validate_po2(po2)?;
        if cycles == 0 || cycles > self.max_guest_cycles {
            return Err(format!("macOS RISC0 requires known cycles in 1..={}, received {cycles}", self.max_guest_cycles));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_limits_and_claim_boundaries() {
        let limits = Risc0Limits::parse(None, true).unwrap();
        assert_eq!(limits.max_guest_cycles, MAX_GUEST_CYCLES);
        assert_eq!(Risc0Limits::parse(None, false).unwrap().max_guest_cycles, 4_194_304);
        for n in ["0", "67108865", "-1", "no", "18446744073709551615"] {
            assert!(Risc0Limits::parse(Some(n), true).is_err());
        }
        let limits = Risc0Limits::parse(Some("10000000"), true).unwrap();
        assert!(limits.validate_guest_cycles(10_000_000).is_ok());
        assert!(limits.validate_guest_cycles(10_000_001).is_err());
        for (cycles, po2) in [(1, 14), (10_000_000, 18)] {
            assert!(limits.validate_claim(cycles, Some(po2)).is_ok());
        }
        assert!(limits.validate_claim(1, Some(20)).is_ok());
        assert!(limits.validate_claim(1, Some(21)).is_ok());
        assert!(Risc0Limits::parse(None, false).unwrap().validate_po2(Some(19)).is_err());
        for (cycles, po2) in [(0, 18), (10_000_001, 18), (1, 13), (1, 22)] {
            assert!(limits.validate_claim(cycles, Some(po2)).is_err());
        }
    }
}
