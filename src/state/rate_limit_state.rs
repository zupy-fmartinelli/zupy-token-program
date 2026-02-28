/// Zero-copy RateLimitState — 57 bytes total.
/// Anchor account discriminator: SHA256("account:RateLimitState")[0..8]
pub struct RateLimitState<'a> {
    data: &'a [u8],
}

pub struct RateLimitStateMut<'a> {
    data: &'a mut [u8],
}

pub const RATE_LIMIT_STATE_DISCRIMINATOR: [u8; 8] = [75, 173, 86, 207, 52, 170, 71, 97];
pub const RATE_LIMIT_STATE_SIZE: usize = 57;

const OFF_DISC: usize = 0;
const OFF_AUTHORITY: usize = 8;
const OFF_CURRENT_DAY: usize = 40;
const OFF_MINTED_TODAY: usize = 48;
const OFF_BUMP: usize = 56;

impl<'a> RateLimitState<'a> {
    pub const SIZE: usize = RATE_LIMIT_STATE_SIZE;
    pub const DISCRIMINATOR: [u8; 8] = RATE_LIMIT_STATE_DISCRIMINATOR;

    pub fn from_slice(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn discriminator(&self) -> &[u8; 8] {
        self.data[OFF_DISC..OFF_DISC + 8].try_into().unwrap()
    }
    pub fn authority(&self) -> &[u8; 32] {
        self.data[OFF_AUTHORITY..OFF_AUTHORITY + 32].try_into().unwrap()
    }
    pub fn current_day(&self) -> u64 {
        u64::from_le_bytes(self.data[OFF_CURRENT_DAY..OFF_CURRENT_DAY + 8].try_into().unwrap())
    }
    pub fn minted_today(&self) -> u64 {
        u64::from_le_bytes(self.data[OFF_MINTED_TODAY..OFF_MINTED_TODAY + 8].try_into().unwrap())
    }
    pub fn bump(&self) -> u8 {
        self.data[OFF_BUMP]
    }
}

impl<'a> RateLimitStateMut<'a> {
    pub fn from_slice(data: &'a mut [u8]) -> Self {
        Self { data }
    }

    pub fn set_discriminator(&mut self, disc: &[u8; 8]) {
        self.data[OFF_DISC..OFF_DISC + 8].copy_from_slice(disc);
    }
    pub fn set_authority(&mut self, pubkey: &[u8; 32]) {
        self.data[OFF_AUTHORITY..OFF_AUTHORITY + 32].copy_from_slice(pubkey);
    }
    pub fn set_current_day(&mut self, val: u64) {
        self.data[OFF_CURRENT_DAY..OFF_CURRENT_DAY + 8].copy_from_slice(&val.to_le_bytes());
    }
    pub fn set_minted_today(&mut self, val: u64) {
        self.data[OFF_MINTED_TODAY..OFF_MINTED_TODAY + 8].copy_from_slice(&val.to_le_bytes());
    }
    pub fn set_bump(&mut self, val: u8) {
        self.data[OFF_BUMP] = val;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_state_size() {
        assert_eq!(RATE_LIMIT_STATE_SIZE, 57);
    }

    #[test]
    fn test_rate_limit_state_discriminator_matches_anchor() {
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(b"account:RateLimitState");
        let expected: [u8; 8] = hash[0..8].try_into().unwrap();
        assert_eq!(RATE_LIMIT_STATE_DISCRIMINATOR, expected);
    }

    #[test]
    fn test_read_write_round_trip() {
        let mut buf = [0u8; RATE_LIMIT_STATE_SIZE];
        let mut state = RateLimitStateMut::from_slice(&mut buf);

        let authority = [42u8; 32];
        state.set_discriminator(&RATE_LIMIT_STATE_DISCRIMINATOR);
        state.set_authority(&authority);
        state.set_current_day(19723);
        state.set_minted_today(500_000_000_000);
        state.set_bump(253);

        let read = RateLimitState::from_slice(&buf);
        assert_eq!(read.discriminator(), &RATE_LIMIT_STATE_DISCRIMINATOR);
        assert_eq!(read.authority(), &authority);
        assert_eq!(read.current_day(), 19723);
        assert_eq!(read.minted_today(), 500_000_000_000);
        assert_eq!(read.bump(), 253);
    }
}
