use crate::constants::SECONDS_PER_DAY;

/// Zero-copy TokenState — 363 bytes total (8 discriminator + 355 data).
/// Anchor account discriminator: SHA256("account:TokenState")[0..8]
pub struct TokenState<'a> {
    data: &'a [u8],
}

/// Mutable variant for write operations.
pub struct TokenStateMut<'a> {
    data: &'a mut [u8],
}

// Anchor account discriminator: SHA256("account:TokenState")[0..8]
pub const TOKEN_STATE_DISCRIMINATOR: [u8; 8] = [218, 112, 6, 149, 55, 186, 168, 163];
pub const TOKEN_STATE_SIZE: usize = 363;

// Byte offsets
const OFF_DISC: usize = 0;
const OFF_TREASURY: usize = 8;
const OFF_MINT_AUTH: usize = 40;
const OFF_TRANSFER_AUTH: usize = 72;
const OFF_POOL_ATA: usize = 104;
const OFF_DIST_POOL: usize = 136;
const OFF_INCENTIVE_POOL: usize = 168;
const OFF_TREASURY_ATA: usize = 200;
const OFF_MINT: usize = 232;
const OFF_INITIALIZED: usize = 264;
const OFF_BUMP: usize = 265;
const OFF_PER_TX_AUTO_LIMIT: usize = 266;
const OFF_DAILY_AUTO_LIMIT: usize = 274;
const OFF_DAILY_MINTED: usize = 282;
const OFF_LAST_RESET_TS: usize = 290;
const OFF_PAUSED: usize = 298;
// OFF_RESERVED: 299..363 (64 bytes)

fn read_pubkey(data: &[u8], offset: usize) -> &[u8; 32] {
    data[offset..offset + 32].try_into().unwrap()
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

fn read_i64(data: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

fn read_bool(data: &[u8], offset: usize) -> bool {
    data[offset] != 0
}

impl<'a> TokenState<'a> {
    pub const SIZE: usize = TOKEN_STATE_SIZE;
    pub const DISCRIMINATOR: [u8; 8] = TOKEN_STATE_DISCRIMINATOR;

    pub fn from_slice(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn discriminator(&self) -> &[u8; 8] {
        self.data[OFF_DISC..OFF_DISC + 8].try_into().unwrap()
    }
    pub fn treasury(&self) -> &[u8; 32] {
        read_pubkey(self.data, OFF_TREASURY)
    }
    pub fn mint_authority(&self) -> &[u8; 32] {
        read_pubkey(self.data, OFF_MINT_AUTH)
    }
    pub fn transfer_authority(&self) -> &[u8; 32] {
        read_pubkey(self.data, OFF_TRANSFER_AUTH)
    }
    pub fn pool_ata(&self) -> &[u8; 32] {
        read_pubkey(self.data, OFF_POOL_ATA)
    }
    pub fn distribution_pool(&self) -> &[u8; 32] {
        read_pubkey(self.data, OFF_DIST_POOL)
    }
    pub fn incentive_pool(&self) -> &[u8; 32] {
        read_pubkey(self.data, OFF_INCENTIVE_POOL)
    }
    pub fn treasury_ata(&self) -> &[u8; 32] {
        read_pubkey(self.data, OFF_TREASURY_ATA)
    }
    pub fn mint(&self) -> &[u8; 32] {
        read_pubkey(self.data, OFF_MINT)
    }
    pub fn initialized(&self) -> bool {
        read_bool(self.data, OFF_INITIALIZED)
    }
    pub fn bump(&self) -> u8 {
        self.data[OFF_BUMP]
    }
    pub fn per_tx_auto_limit(&self) -> u64 {
        read_u64(self.data, OFF_PER_TX_AUTO_LIMIT)
    }
    pub fn daily_auto_limit(&self) -> u64 {
        read_u64(self.data, OFF_DAILY_AUTO_LIMIT)
    }
    pub fn daily_minted(&self) -> u64 {
        read_u64(self.data, OFF_DAILY_MINTED)
    }
    pub fn last_reset_timestamp(&self) -> i64 {
        read_i64(self.data, OFF_LAST_RESET_TS)
    }
    pub fn paused(&self) -> bool {
        read_bool(self.data, OFF_PAUSED)
    }

    // Helper methods
    pub fn is_mint_authority(&self, pubkey: &[u8; 32]) -> bool {
        self.mint_authority() == pubkey
    }
    pub fn is_transfer_authority(&self, pubkey: &[u8; 32]) -> bool {
        self.transfer_authority() == pubkey
    }
    pub fn is_treasury(&self, pubkey: &[u8; 32]) -> bool {
        self.treasury() == pubkey
    }
    pub fn within_tx_limit(&self, amount: u64) -> bool {
        amount <= self.per_tx_auto_limit()
    }
    pub fn within_daily_limit(&self, amount: u64) -> bool {
        self.daily_minted().saturating_add(amount) <= self.daily_auto_limit()
    }
}

impl<'a> TokenStateMut<'a> {
    pub fn from_slice(data: &'a mut [u8]) -> Self {
        Self { data }
    }

    // Read accessors (delegate to immutable)
    pub fn discriminator(&self) -> &[u8; 8] {
        self.data[OFF_DISC..OFF_DISC + 8].try_into().unwrap()
    }
    pub fn daily_minted(&self) -> u64 {
        read_u64(self.data, OFF_DAILY_MINTED)
    }
    pub fn last_reset_timestamp(&self) -> i64 {
        read_i64(self.data, OFF_LAST_RESET_TS)
    }
    pub fn bump(&self) -> u8 {
        self.data[OFF_BUMP]
    }

    // Write accessors
    pub fn set_discriminator(&mut self, disc: &[u8; 8]) {
        self.data[OFF_DISC..OFF_DISC + 8].copy_from_slice(disc);
    }
    pub fn set_treasury(&mut self, pubkey: &[u8; 32]) {
        self.data[OFF_TREASURY..OFF_TREASURY + 32].copy_from_slice(pubkey);
    }
    pub fn set_mint_authority(&mut self, pubkey: &[u8; 32]) {
        self.data[OFF_MINT_AUTH..OFF_MINT_AUTH + 32].copy_from_slice(pubkey);
    }
    pub fn set_transfer_authority(&mut self, pubkey: &[u8; 32]) {
        self.data[OFF_TRANSFER_AUTH..OFF_TRANSFER_AUTH + 32].copy_from_slice(pubkey);
    }
    pub fn set_pool_ata(&mut self, pubkey: &[u8; 32]) {
        self.data[OFF_POOL_ATA..OFF_POOL_ATA + 32].copy_from_slice(pubkey);
    }
    pub fn set_distribution_pool(&mut self, pubkey: &[u8; 32]) {
        self.data[OFF_DIST_POOL..OFF_DIST_POOL + 32].copy_from_slice(pubkey);
    }
    pub fn set_incentive_pool(&mut self, pubkey: &[u8; 32]) {
        self.data[OFF_INCENTIVE_POOL..OFF_INCENTIVE_POOL + 32].copy_from_slice(pubkey);
    }
    pub fn set_treasury_ata(&mut self, pubkey: &[u8; 32]) {
        self.data[OFF_TREASURY_ATA..OFF_TREASURY_ATA + 32].copy_from_slice(pubkey);
    }
    pub fn set_mint(&mut self, pubkey: &[u8; 32]) {
        self.data[OFF_MINT..OFF_MINT + 32].copy_from_slice(pubkey);
    }
    pub fn set_initialized(&mut self, val: bool) {
        self.data[OFF_INITIALIZED] = val as u8;
    }
    pub fn set_bump(&mut self, val: u8) {
        self.data[OFF_BUMP] = val;
    }
    pub fn set_per_tx_auto_limit(&mut self, val: u64) {
        self.data[OFF_PER_TX_AUTO_LIMIT..OFF_PER_TX_AUTO_LIMIT + 8]
            .copy_from_slice(&val.to_le_bytes());
    }
    pub fn set_daily_auto_limit(&mut self, val: u64) {
        self.data[OFF_DAILY_AUTO_LIMIT..OFF_DAILY_AUTO_LIMIT + 8]
            .copy_from_slice(&val.to_le_bytes());
    }
    pub fn set_daily_minted(&mut self, val: u64) {
        self.data[OFF_DAILY_MINTED..OFF_DAILY_MINTED + 8]
            .copy_from_slice(&val.to_le_bytes());
    }
    pub fn set_last_reset_timestamp(&mut self, val: i64) {
        self.data[OFF_LAST_RESET_TS..OFF_LAST_RESET_TS + 8]
            .copy_from_slice(&val.to_le_bytes());
    }
    pub fn set_paused(&mut self, val: bool) {
        self.data[OFF_PAUSED] = val as u8;
    }

    /// Reset daily minted if a new day has started.
    pub fn maybe_reset_daily(&mut self, current_timestamp: i64) {
        let current_day = current_timestamp / SECONDS_PER_DAY;
        let last_day = self.last_reset_timestamp() / SECONDS_PER_DAY;
        if current_day > last_day {
            self.set_daily_minted(0);
            self.set_last_reset_timestamp(current_timestamp);
        }
    }

    /// Record a mint operation (saturating add to daily_minted).
    pub fn record_mint(&mut self, amount: u64) {
        let new_total = self.daily_minted().saturating_add(amount);
        self.set_daily_minted(new_total);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_state_size() {
        assert_eq!(TOKEN_STATE_SIZE, 363);
    }

    #[test]
    fn test_token_state_discriminator_matches_anchor() {
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(b"account:TokenState");
        let expected: [u8; 8] = hash[0..8].try_into().unwrap();
        assert_eq!(TOKEN_STATE_DISCRIMINATOR, expected);
    }

    #[test]
    fn test_read_write_round_trip_pubkeys() {
        let mut buf = [0u8; TOKEN_STATE_SIZE];
        let mut state = TokenStateMut::from_slice(&mut buf);

        let treasury = [1u8; 32];
        let mint_auth = [2u8; 32];
        let transfer_auth = [3u8; 32];
        let pool_ata = [4u8; 32];
        let dist_pool = [5u8; 32];
        let incentive_pool = [6u8; 32];
        let treasury_ata = [7u8; 32];
        let mint = [8u8; 32];

        state.set_treasury(&treasury);
        state.set_mint_authority(&mint_auth);
        state.set_transfer_authority(&transfer_auth);
        state.set_pool_ata(&pool_ata);
        state.set_distribution_pool(&dist_pool);
        state.set_incentive_pool(&incentive_pool);
        state.set_treasury_ata(&treasury_ata);
        state.set_mint(&mint);

        let read = TokenState::from_slice(&buf);
        assert_eq!(read.treasury(), &treasury);
        assert_eq!(read.mint_authority(), &mint_auth);
        assert_eq!(read.transfer_authority(), &transfer_auth);
        assert_eq!(read.pool_ata(), &pool_ata);
        assert_eq!(read.distribution_pool(), &dist_pool);
        assert_eq!(read.incentive_pool(), &incentive_pool);
        assert_eq!(read.treasury_ata(), &treasury_ata);
        assert_eq!(read.mint(), &mint);
    }

    #[test]
    fn test_read_write_round_trip_scalars() {
        let mut buf = [0u8; TOKEN_STATE_SIZE];
        let mut state = TokenStateMut::from_slice(&mut buf);

        state.set_discriminator(&TOKEN_STATE_DISCRIMINATOR);
        state.set_initialized(true);
        state.set_bump(254);
        state.set_per_tx_auto_limit(100_000_000_000);
        state.set_daily_auto_limit(500_000_000_000);
        state.set_daily_minted(42_000_000);
        state.set_last_reset_timestamp(1_700_000_000);
        state.set_paused(false);

        let read = TokenState::from_slice(&buf);
        assert_eq!(read.discriminator(), &TOKEN_STATE_DISCRIMINATOR);
        assert!(read.initialized());
        assert_eq!(read.bump(), 254);
        assert_eq!(read.per_tx_auto_limit(), 100_000_000_000);
        assert_eq!(read.daily_auto_limit(), 500_000_000_000);
        assert_eq!(read.daily_minted(), 42_000_000);
        assert_eq!(read.last_reset_timestamp(), 1_700_000_000);
        assert!(!read.paused());
    }

    #[test]
    fn test_helper_methods() {
        let mut buf = [0u8; TOKEN_STATE_SIZE];
        let mut state = TokenStateMut::from_slice(&mut buf);

        let treasury = [10u8; 32];
        let mint_auth = [20u8; 32];
        let transfer_auth = [30u8; 32];

        state.set_treasury(&treasury);
        state.set_mint_authority(&mint_auth);
        state.set_transfer_authority(&transfer_auth);
        state.set_per_tx_auto_limit(1000);
        state.set_daily_auto_limit(5000);
        state.set_daily_minted(2000);

        let read = TokenState::from_slice(&buf);
        assert!(read.is_treasury(&treasury));
        assert!(!read.is_treasury(&mint_auth));
        assert!(read.is_mint_authority(&mint_auth));
        assert!(read.is_transfer_authority(&transfer_auth));
        assert!(read.within_tx_limit(1000));
        assert!(!read.within_tx_limit(1001));
        assert!(read.within_daily_limit(3000));
        assert!(!read.within_daily_limit(3001));
    }

    #[test]
    fn test_token_state_mut_read_accessors() {
        let mut buf = [0u8; TOKEN_STATE_SIZE];
        let mut state = TokenStateMut::from_slice(&mut buf);

        state.set_discriminator(&TOKEN_STATE_DISCRIMINATOR);
        state.set_bump(42);
        state.set_daily_minted(12345);
        state.set_last_reset_timestamp(9999);

        // Test read accessors on mutable variant
        assert_eq!(state.discriminator(), &TOKEN_STATE_DISCRIMINATOR);
        assert_eq!(state.bump(), 42);
        assert_eq!(state.daily_minted(), 12345);
        assert_eq!(state.last_reset_timestamp(), 9999);
    }

    #[test]
    fn test_maybe_reset_daily() {
        let mut buf = [0u8; TOKEN_STATE_SIZE];
        let mut state = TokenStateMut::from_slice(&mut buf);

        // Day 0: set initial state
        state.set_daily_minted(50000);
        state.set_last_reset_timestamp(86_400); // start of day 1

        // Same day — should NOT reset
        state.maybe_reset_daily(86_400 + 100);
        assert_eq!(state.daily_minted(), 50000);

        // Next day — SHOULD reset
        state.maybe_reset_daily(86_400 * 2 + 1);
        assert_eq!(state.daily_minted(), 0);
    }

    #[test]
    fn test_record_mint() {
        let mut buf = [0u8; TOKEN_STATE_SIZE];
        let mut state = TokenStateMut::from_slice(&mut buf);

        state.set_daily_minted(100);
        state.record_mint(50);
        assert_eq!(state.daily_minted(), 150);

        // Saturating add at max
        state.set_daily_minted(u64::MAX - 10);
        state.record_mint(20);
        assert_eq!(state.daily_minted(), u64::MAX);
    }
}
