use pinocchio::error::ProgramError;

use crate::constants::{MEMO_PREFIX, MEMO_VERSION};
use crate::error::ZupyTokenError;

/// Validate memo format: `"zupy:v1:{source}:{source_id}"`
///
/// Rules:
/// - Must have exactly 4 colon-separated segments
/// - Segment 0 must be `MEMO_PREFIX` ("zupy")
/// - Segment 1 must be `MEMO_VERSION` ("v1")
/// - Segments 2 and 3 (source and source_id) must be non-empty
pub fn validate_memo_format(memo: &str) -> Result<(), ProgramError> {
    let mut parts = memo.splitn(4, ':');

    let prefix = parts.next().ok_or(ProgramError::from(ZupyTokenError::InvalidMemoFormat))?;
    if prefix != MEMO_PREFIX {
        return Err(ZupyTokenError::InvalidMemoFormat.into());
    }

    let version = parts.next().ok_or(ProgramError::from(ZupyTokenError::InvalidMemoFormat))?;
    if version != MEMO_VERSION {
        return Err(ZupyTokenError::InvalidMemoFormat.into());
    }

    let source = parts.next().ok_or(ProgramError::from(ZupyTokenError::InvalidMemoFormat))?;
    if source.is_empty() {
        return Err(ZupyTokenError::InvalidMemoFormat.into());
    }

    let source_id = parts.next().ok_or(ProgramError::from(ZupyTokenError::InvalidMemoFormat))?;
    if source_id.is_empty() {
        return Err(ZupyTokenError::InvalidMemoFormat.into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Valid memo tests ────────────────────────────────────────────────

    #[test]
    fn test_valid_memo_transfer() {
        assert!(validate_memo_format("zupy:v1:transfer:12345").is_ok());
    }

    #[test]
    fn test_valid_memo_mint() {
        assert!(validate_memo_format("zupy:v1:mint:67890").is_ok());
    }

    #[test]
    fn test_valid_memo_burn() {
        assert!(validate_memo_format("zupy:v1:burn:abc-def").is_ok());
    }

    #[test]
    fn test_valid_memo_with_ksuid() {
        assert!(validate_memo_format("zupy:v1:restock:0ujsszwN8NRY24YaXiTIE2VWDTS").is_ok());
    }

    #[test]
    fn test_valid_memo_with_colons_in_source_id() {
        // splitn(4, ':') means the 4th segment can contain colons
        assert!(validate_memo_format("zupy:v1:split:a:b:c").is_ok());
    }

    // ── Invalid memo tests ──────────────────────────────────────────────

    #[test]
    fn test_invalid_memo_empty() {
        let result = validate_memo_format("");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidMemoFormat as u32));
    }

    #[test]
    fn test_invalid_memo_wrong_prefix() {
        assert!(validate_memo_format("zepy:v1:transfer:123").is_err());
    }

    #[test]
    fn test_invalid_memo_wrong_version() {
        assert!(validate_memo_format("zupy:v2:transfer:123").is_err());
    }

    #[test]
    fn test_invalid_memo_missing_source() {
        assert!(validate_memo_format("zupy:v1").is_err());
    }

    #[test]
    fn test_invalid_memo_empty_source() {
        assert!(validate_memo_format("zupy:v1::123").is_err());
    }

    #[test]
    fn test_invalid_memo_missing_source_id() {
        assert!(validate_memo_format("zupy:v1:transfer").is_err());
    }

    #[test]
    fn test_invalid_memo_empty_source_id() {
        assert!(validate_memo_format("zupy:v1:transfer:").is_err());
    }

    #[test]
    fn test_invalid_memo_only_prefix() {
        assert!(validate_memo_format("zupy").is_err());
    }

    #[test]
    fn test_invalid_memo_no_colons() {
        assert!(validate_memo_format("random_string").is_err());
    }
}
