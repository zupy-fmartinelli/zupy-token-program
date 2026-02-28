use pinocchio::error::ProgramError;

/// Parse a u64 (8-byte little-endian) from instruction data at the given offset.
/// Returns `InvalidInstructionData` if not enough bytes remain.
#[inline(always)]
pub fn parse_u64(data: &[u8], offset: usize) -> Result<u64, ProgramError> {
    let end = offset.checked_add(8).ok_or(ProgramError::InvalidInstructionData)?;
    if data.len() < end {
        return Err(ProgramError::InvalidInstructionData);
    }
    Ok(u64::from_le_bytes(
        data[offset..offset + 8].try_into().unwrap(),
    ))
}

/// Parse a single bool (1 byte: 0=false, non-zero=true) from instruction data at the given offset.
/// Returns `InvalidInstructionData` if not enough bytes remain.
#[inline(always)]
pub fn parse_bool(data: &[u8], offset: usize) -> Result<bool, ProgramError> {
    let end = offset.checked_add(1).ok_or(ProgramError::InvalidInstructionData)?;
    if data.len() < end {
        return Err(ProgramError::InvalidInstructionData);
    }
    Ok(data[offset] != 0)
}

/// Parse a single u8 from instruction data at the given offset.
/// Returns `InvalidInstructionData` if not enough bytes remain.
#[inline(always)]
pub fn parse_u8(data: &[u8], offset: usize) -> Result<u8, ProgramError> {
    let end = offset.checked_add(1).ok_or(ProgramError::InvalidInstructionData)?;
    if data.len() < end {
        return Err(ProgramError::InvalidInstructionData);
    }
    Ok(data[offset])
}

/// Parse a 32-byte pubkey from instruction data at the given offset.
/// Returns a reference to the 32-byte slice and the new offset past the pubkey.
/// Returns `InvalidInstructionData` if not enough bytes remain.
#[inline(always)]
pub fn parse_pubkey(data: &[u8], offset: usize) -> Result<(&[u8; 32], usize), ProgramError> {
    let end = offset.checked_add(32).ok_or(ProgramError::InvalidInstructionData)?;
    if data.len() < end {
        return Err(ProgramError::InvalidInstructionData);
    }
    let pubkey: &[u8; 32] = data[offset..end].try_into().unwrap();
    Ok((pubkey, end))
}

/// Parse a fixed-size byte array from instruction data at the given offset.
/// Returns a reference to the N-byte slice and the new offset past the bytes.
/// Returns `InvalidInstructionData` if not enough bytes remain.
#[inline(always)]
pub fn parse_bytes<const N: usize>(data: &[u8], offset: usize) -> Result<(&[u8; N], usize), ProgramError> {
    let end = offset.checked_add(N).ok_or(ProgramError::InvalidInstructionData)?;
    if data.len() < end {
        return Err(ProgramError::InvalidInstructionData);
    }
    let bytes: &[u8; N] = data[offset..end].try_into().unwrap();
    Ok((bytes, end))
}

/// Parse a Borsh-encoded String (4-byte u32 LE length prefix + UTF-8 bytes)
/// from instruction data at the given offset.
/// Returns the string slice and the new offset past the string.
/// Returns `InvalidInstructionData` if data is truncated or not valid UTF-8.
#[inline(always)]
pub fn parse_string(data: &[u8], offset: usize) -> Result<(&str, usize), ProgramError> {
    let len_end = offset.checked_add(4).ok_or(ProgramError::InvalidInstructionData)?;
    if data.len() < len_end {
        return Err(ProgramError::InvalidInstructionData);
    }
    let len = u32::from_le_bytes(data[offset..len_end].try_into().unwrap()) as usize;
    let str_start = len_end;
    let str_end = str_start.checked_add(len).ok_or(ProgramError::InvalidInstructionData)?;
    if data.len() < str_end {
        return Err(ProgramError::InvalidInstructionData);
    }
    let s = core::str::from_utf8(&data[str_start..str_end])
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    Ok((s, str_end))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_u64 tests ─────────────────────────────────────────────────

    #[test]
    fn test_parse_u64_valid() {
        let data = 1000u64.to_le_bytes();
        let result = parse_u64(&data, 0).unwrap();
        assert_eq!(result, 1000);
    }

    #[test]
    fn test_parse_u64_at_offset() {
        let mut data = vec![0u8; 4]; // padding
        data.extend_from_slice(&42u64.to_le_bytes());
        let result = parse_u64(&data, 4).unwrap();
        assert_eq!(result, 42);
    }

    #[test]
    fn test_parse_u64_max_value() {
        let data = u64::MAX.to_le_bytes();
        let result = parse_u64(&data, 0).unwrap();
        assert_eq!(result, u64::MAX);
    }

    #[test]
    fn test_parse_u64_zero() {
        let data = 0u64.to_le_bytes();
        let result = parse_u64(&data, 0).unwrap();
        assert_eq!(result, 0);
    }

    #[test]
    fn test_parse_u64_truncated() {
        let data = [0u8; 7]; // only 7 bytes, need 8
        let result = parse_u64(&data, 0);
        assert_eq!(result.unwrap_err(), ProgramError::InvalidInstructionData);
    }

    #[test]
    fn test_parse_u64_truncated_at_offset() {
        let data = [0u8; 10]; // 10 bytes total
        let result = parse_u64(&data, 5); // need bytes 5..13, only have 10
        assert_eq!(result.unwrap_err(), ProgramError::InvalidInstructionData);
    }

    #[test]
    fn test_parse_u64_empty_data() {
        let data: &[u8] = &[];
        let result = parse_u64(data, 0);
        assert_eq!(result.unwrap_err(), ProgramError::InvalidInstructionData);
    }

    #[test]
    fn test_parse_u64_offset_overflow() {
        let data = [0u8; 8];
        let result = parse_u64(&data, usize::MAX - 3); // offset + 8 would overflow
        assert_eq!(result.unwrap_err(), ProgramError::InvalidInstructionData);
    }

    // ── parse_bool tests ──────────────────────────────────────────────

    #[test]
    fn test_parse_bool_true() {
        assert!(parse_bool(&[1], 0).unwrap());
    }

    #[test]
    fn test_parse_bool_false() {
        assert!(!parse_bool(&[0], 0).unwrap());
    }

    #[test]
    fn test_parse_bool_nonzero_is_true() {
        assert!(parse_bool(&[255], 0).unwrap());
        assert!(parse_bool(&[42], 0).unwrap());
    }

    #[test]
    fn test_parse_bool_at_offset() {
        assert!(parse_bool(&[0, 0, 1], 2).unwrap());
    }

    #[test]
    fn test_parse_bool_empty() {
        assert_eq!(parse_bool(&[], 0).unwrap_err(), ProgramError::InvalidInstructionData);
    }

    #[test]
    fn test_parse_bool_offset_overflow() {
        assert_eq!(parse_bool(&[1], usize::MAX).unwrap_err(), ProgramError::InvalidInstructionData);
    }

    // ── parse_u8 tests ───────────────────────────────────────────────

    #[test]
    fn test_parse_u8_valid() {
        assert_eq!(parse_u8(&[42], 0).unwrap(), 42);
    }

    #[test]
    fn test_parse_u8_at_offset() {
        assert_eq!(parse_u8(&[0, 0, 99], 2).unwrap(), 99);
    }

    #[test]
    fn test_parse_u8_empty() {
        assert_eq!(parse_u8(&[], 0).unwrap_err(), ProgramError::InvalidInstructionData);
    }

    #[test]
    fn test_parse_u8_offset_overflow() {
        assert_eq!(parse_u8(&[1], usize::MAX).unwrap_err(), ProgramError::InvalidInstructionData);
    }

    // ── parse_pubkey tests ───────────────────────────────────────────

    #[test]
    fn test_parse_pubkey_valid() {
        let mut data = [0u8; 32];
        data[0] = 1;
        data[31] = 255;
        let (pubkey, end) = parse_pubkey(&data, 0).unwrap();
        assert_eq!(pubkey[0], 1);
        assert_eq!(pubkey[31], 255);
        assert_eq!(end, 32);
    }

    #[test]
    fn test_parse_pubkey_at_offset() {
        let mut data = vec![0u8; 8];
        data.extend_from_slice(&[42u8; 32]);
        let (pubkey, end) = parse_pubkey(&data, 8).unwrap();
        assert_eq!(pubkey, &[42u8; 32]);
        assert_eq!(end, 40);
    }

    #[test]
    fn test_parse_pubkey_truncated() {
        let data = [0u8; 31]; // need 32
        assert_eq!(parse_pubkey(&data, 0).unwrap_err(), ProgramError::InvalidInstructionData);
    }

    #[test]
    fn test_parse_pubkey_offset_overflow() {
        let data = [0u8; 32];
        assert_eq!(parse_pubkey(&data, usize::MAX).unwrap_err(), ProgramError::InvalidInstructionData);
    }

    // ── parse_bytes tests ────────────────────────────────────────────

    #[test]
    fn test_parse_bytes_27() {
        let data = [7u8; 27];
        let (bytes, end) = parse_bytes::<27>(&data, 0).unwrap();
        assert_eq!(bytes, &[7u8; 27]);
        assert_eq!(end, 27);
    }

    #[test]
    fn test_parse_bytes_at_offset() {
        let mut data = vec![0u8; 4];
        data.extend_from_slice(&[0xAB; 8]);
        let (bytes, end) = parse_bytes::<8>(&data, 4).unwrap();
        assert_eq!(bytes, &[0xAB; 8]);
        assert_eq!(end, 12);
    }

    #[test]
    fn test_parse_bytes_truncated() {
        let data = [0u8; 10];
        assert_eq!(parse_bytes::<27>(&data, 0).unwrap_err(), ProgramError::InvalidInstructionData);
    }

    #[test]
    fn test_parse_bytes_offset_overflow() {
        let data = [0u8; 27];
        assert_eq!(parse_bytes::<27>(&data, usize::MAX).unwrap_err(), ProgramError::InvalidInstructionData);
    }

    // ── parse_string tests ──────────────────────────────────────────────

    #[test]
    fn test_parse_string_valid() {
        let memo = "zupy:v1:transfer:12345";
        let mut data = (memo.len() as u32).to_le_bytes().to_vec();
        data.extend_from_slice(memo.as_bytes());
        let (result, new_offset) = parse_string(&data, 0).unwrap();
        assert_eq!(result, memo);
        assert_eq!(new_offset, 4 + memo.len());
    }

    #[test]
    fn test_parse_string_at_offset() {
        let memo = "hello";
        let mut data = vec![0u8; 8]; // padding
        data.extend_from_slice(&(memo.len() as u32).to_le_bytes());
        data.extend_from_slice(memo.as_bytes());
        let (result, new_offset) = parse_string(&data, 8).unwrap();
        assert_eq!(result, memo);
        assert_eq!(new_offset, 8 + 4 + memo.len());
    }

    #[test]
    fn test_parse_string_empty_string() {
        let data = 0u32.to_le_bytes();
        let (result, new_offset) = parse_string(&data, 0).unwrap();
        assert_eq!(result, "");
        assert_eq!(new_offset, 4);
    }

    #[test]
    fn test_parse_string_truncated_length_prefix() {
        let data = [0u8; 3]; // only 3 bytes, need 4 for length
        let result = parse_string(&data, 0);
        assert_eq!(result.unwrap_err(), ProgramError::InvalidInstructionData);
    }

    #[test]
    fn test_parse_string_truncated_body() {
        // Length says 10, but only 5 bytes available
        let mut data = 10u32.to_le_bytes().to_vec();
        data.extend_from_slice(b"hello"); // 5 bytes, not 10
        let result = parse_string(&data, 0);
        assert_eq!(result.unwrap_err(), ProgramError::InvalidInstructionData);
    }

    #[test]
    fn test_parse_string_invalid_utf8() {
        let bad_bytes: &[u8] = &[0xFF, 0xFE, 0xFD];
        let mut data = (bad_bytes.len() as u32).to_le_bytes().to_vec();
        data.extend_from_slice(bad_bytes);
        let result = parse_string(&data, 0);
        assert_eq!(result.unwrap_err(), ProgramError::InvalidInstructionData);
    }

    #[test]
    fn test_parse_string_no_data_after_length() {
        let data: &[u8] = &[];
        let result = parse_string(data, 0);
        assert_eq!(result.unwrap_err(), ProgramError::InvalidInstructionData);
    }

    #[test]
    fn test_parse_u64_then_string_sequential() {
        // Simulate transfer_from_pool data: amount (u64) + memo (String)
        let amount = 1_000_000u64;
        let memo = "zupy:v1:transfer:999";
        let mut data = Vec::new();
        data.extend_from_slice(&amount.to_le_bytes());
        data.extend_from_slice(&(memo.len() as u32).to_le_bytes());
        data.extend_from_slice(memo.as_bytes());

        let parsed_amount = parse_u64(&data, 0).unwrap();
        assert_eq!(parsed_amount, amount);

        let (parsed_memo, end) = parse_string(&data, 8).unwrap();
        assert_eq!(parsed_memo, memo);
        assert_eq!(end, data.len());
    }

    #[test]
    fn test_parse_multiple_u64_then_string() {
        // Simulate transfer_company_to_user: company_id (u64) + user_id (u64) + amount (u64) + memo (String)
        let company_id = 42u64;
        let user_id = 99u64;
        let amount = 500_000u64;
        let memo = "zupy:v1:reward:abc";
        let mut data = Vec::new();
        data.extend_from_slice(&company_id.to_le_bytes());
        data.extend_from_slice(&user_id.to_le_bytes());
        data.extend_from_slice(&amount.to_le_bytes());
        data.extend_from_slice(&(memo.len() as u32).to_le_bytes());
        data.extend_from_slice(memo.as_bytes());

        assert_eq!(parse_u64(&data, 0).unwrap(), company_id);
        assert_eq!(parse_u64(&data, 8).unwrap(), user_id);
        assert_eq!(parse_u64(&data, 16).unwrap(), amount);
        let (parsed_memo, end) = parse_string(&data, 24).unwrap();
        assert_eq!(parsed_memo, memo);
        assert_eq!(end, data.len());
    }
}
