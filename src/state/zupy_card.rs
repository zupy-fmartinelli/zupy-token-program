/// Zero-copy ZupyCard — 108 bytes total.
/// Anchor account discriminator: SHA256("account:ZupyCard")[0..8]
pub struct ZupyCard<'a> {
    data: &'a [u8],
}

pub struct ZupyCardMut<'a> {
    data: &'a mut [u8],
}

pub const ZUPY_CARD_DISCRIMINATOR: [u8; 8] = [254, 50, 30, 179, 82, 218, 229, 232];
pub const ZUPY_CARD_SIZE: usize = 108;

const OFF_DISC: usize = 0;
const OFF_OWNER: usize = 8;
const OFF_MINT: usize = 40;
const OFF_USER_KSUID: usize = 72;
const OFF_CREATED_AT: usize = 99;
const OFF_BUMP: usize = 107;

impl<'a> ZupyCard<'a> {
    pub const SIZE: usize = ZUPY_CARD_SIZE;
    pub const DISCRIMINATOR: [u8; 8] = ZUPY_CARD_DISCRIMINATOR;

    pub fn from_slice(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn discriminator(&self) -> &[u8; 8] {
        self.data[OFF_DISC..OFF_DISC + 8].try_into().unwrap()
    }
    pub fn owner(&self) -> &[u8; 32] {
        self.data[OFF_OWNER..OFF_OWNER + 32].try_into().unwrap()
    }
    pub fn mint(&self) -> &[u8; 32] {
        self.data[OFF_MINT..OFF_MINT + 32].try_into().unwrap()
    }
    pub fn user_ksuid(&self) -> &[u8; 27] {
        self.data[OFF_USER_KSUID..OFF_USER_KSUID + 27].try_into().unwrap()
    }
    pub fn created_at(&self) -> i64 {
        i64::from_le_bytes(self.data[OFF_CREATED_AT..OFF_CREATED_AT + 8].try_into().unwrap())
    }
    pub fn bump(&self) -> u8 {
        self.data[OFF_BUMP]
    }
}

impl<'a> ZupyCardMut<'a> {
    pub fn from_slice(data: &'a mut [u8]) -> Self {
        Self { data }
    }

    pub fn set_discriminator(&mut self, disc: &[u8; 8]) {
        self.data[OFF_DISC..OFF_DISC + 8].copy_from_slice(disc);
    }
    pub fn set_owner(&mut self, pubkey: &[u8; 32]) {
        self.data[OFF_OWNER..OFF_OWNER + 32].copy_from_slice(pubkey);
    }
    pub fn set_mint(&mut self, pubkey: &[u8; 32]) {
        self.data[OFF_MINT..OFF_MINT + 32].copy_from_slice(pubkey);
    }
    pub fn set_user_ksuid(&mut self, ksuid: &[u8; 27]) {
        self.data[OFF_USER_KSUID..OFF_USER_KSUID + 27].copy_from_slice(ksuid);
    }
    pub fn set_created_at(&mut self, val: i64) {
        self.data[OFF_CREATED_AT..OFF_CREATED_AT + 8].copy_from_slice(&val.to_le_bytes());
    }
    pub fn set_bump(&mut self, val: u8) {
        self.data[OFF_BUMP] = val;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zupy_card_size() {
        assert_eq!(ZUPY_CARD_SIZE, 108);
    }

    #[test]
    fn test_zupy_card_discriminator_matches_anchor() {
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(b"account:ZupyCard");
        let expected: [u8; 8] = hash[0..8].try_into().unwrap();
        assert_eq!(ZUPY_CARD_DISCRIMINATOR, expected);
    }

    #[test]
    fn test_read_write_round_trip() {
        let mut buf = [0u8; ZUPY_CARD_SIZE];
        let mut state = ZupyCardMut::from_slice(&mut buf);

        let owner = [11u8; 32];
        let mint = [22u8; 32];
        let ksuid = [b'A'; 27];

        state.set_discriminator(&ZUPY_CARD_DISCRIMINATOR);
        state.set_owner(&owner);
        state.set_mint(&mint);
        state.set_user_ksuid(&ksuid);
        state.set_created_at(1_700_000_000);
        state.set_bump(250);

        let read = ZupyCard::from_slice(&buf);
        assert_eq!(read.discriminator(), &ZUPY_CARD_DISCRIMINATOR);
        assert_eq!(read.owner(), &owner);
        assert_eq!(read.mint(), &mint);
        assert_eq!(read.user_ksuid(), &ksuid);
        assert_eq!(read.created_at(), 1_700_000_000);
        assert_eq!(read.bump(), 250);
    }
}
