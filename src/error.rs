use pinocchio::error::ProgramError;

/// All 30 error codes matching Anchor program (6000-6029).
/// Django compatibility requires identical Custom(code) values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ZupyTokenError {
    InvalidAuthority = 6000,
    DailyLimitExceeded = 6001,
    TxLimitExceeded = 6002,
    AlreadyInitialized = 6003,
    InsufficientBalance = 6004,
    InvalidAmount = 6005,
    RateLimitNotInitialized = 6006,
    InvalidPDA = 6007,
    DuplicateMemo = 6008,
    InvalidMemoFormat = 6009,
    NotInitialized = 6010,
    InvalidMint = 6011,
    ZeroAmount = 6012,
    InvalidMetadataName = 6013,
    InvalidMetadataSymbol = 6014,
    InvalidMetadataUri = 6015,
    ExtensionCalculationError = 6016,
    InvalidPoolAccount = 6017,
    SystemPaused = 6018,
    UnauthorizedTreasury = 6019,
    ExceedsTransactionLimit = 6020,
    ExceedsDailyLimit = 6021,
    InvalidTreasuryAccount = 6022,
    InvalidIncentivePool = 6023,
    InsufficientPoolBalance = 6024,
    InvalidTokenProgram = 6025,
    NotImplemented = 6026,
    InvalidMetadataPDA = 6027,
    InvalidOperationType = 6028,
    SplitCalculationError = 6029,
}

impl From<ZupyTokenError> for ProgramError {
    fn from(e: ZupyTokenError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AC6: All 30 error codes map to ProgramError::Custom(6000 + N)
    #[test]
    fn test_all_error_codes_match_anchor_values() {
        let expected: [(ZupyTokenError, u32); 30] = [
            (ZupyTokenError::InvalidAuthority, 6000),
            (ZupyTokenError::DailyLimitExceeded, 6001),
            (ZupyTokenError::TxLimitExceeded, 6002),
            (ZupyTokenError::AlreadyInitialized, 6003),
            (ZupyTokenError::InsufficientBalance, 6004),
            (ZupyTokenError::InvalidAmount, 6005),
            (ZupyTokenError::RateLimitNotInitialized, 6006),
            (ZupyTokenError::InvalidPDA, 6007),
            (ZupyTokenError::DuplicateMemo, 6008),
            (ZupyTokenError::InvalidMemoFormat, 6009),
            (ZupyTokenError::NotInitialized, 6010),
            (ZupyTokenError::InvalidMint, 6011),
            (ZupyTokenError::ZeroAmount, 6012),
            (ZupyTokenError::InvalidMetadataName, 6013),
            (ZupyTokenError::InvalidMetadataSymbol, 6014),
            (ZupyTokenError::InvalidMetadataUri, 6015),
            (ZupyTokenError::ExtensionCalculationError, 6016),
            (ZupyTokenError::InvalidPoolAccount, 6017),
            (ZupyTokenError::SystemPaused, 6018),
            (ZupyTokenError::UnauthorizedTreasury, 6019),
            (ZupyTokenError::ExceedsTransactionLimit, 6020),
            (ZupyTokenError::ExceedsDailyLimit, 6021),
            (ZupyTokenError::InvalidTreasuryAccount, 6022),
            (ZupyTokenError::InvalidIncentivePool, 6023),
            (ZupyTokenError::InsufficientPoolBalance, 6024),
            (ZupyTokenError::InvalidTokenProgram, 6025),
            (ZupyTokenError::NotImplemented, 6026),
            (ZupyTokenError::InvalidMetadataPDA, 6027),
            (ZupyTokenError::InvalidOperationType, 6028),
            (ZupyTokenError::SplitCalculationError, 6029),
        ];

        for (error, code) in expected {
            assert_eq!(error as u32, code, "Error {:?} should have code {}", error, code);
        }
    }

    /// AC6: From<ZupyTokenError> for ProgramError yields Custom(code)
    #[test]
    fn test_from_zupy_error_to_program_error() {
        let pe: ProgramError = ZupyTokenError::InvalidAuthority.into();
        assert_eq!(pe, ProgramError::Custom(6000));

        let pe: ProgramError = ZupyTokenError::SplitCalculationError.into();
        assert_eq!(pe, ProgramError::Custom(6029));

        let pe: ProgramError = ZupyTokenError::SystemPaused.into();
        assert_eq!(pe, ProgramError::Custom(6018));
    }

    /// Verify all error variants can be converted to ProgramError
    #[test]
    fn test_all_errors_convert_to_program_error() {
        let errors: [ZupyTokenError; 30] = [
            ZupyTokenError::InvalidAuthority,
            ZupyTokenError::DailyLimitExceeded,
            ZupyTokenError::TxLimitExceeded,
            ZupyTokenError::AlreadyInitialized,
            ZupyTokenError::InsufficientBalance,
            ZupyTokenError::InvalidAmount,
            ZupyTokenError::RateLimitNotInitialized,
            ZupyTokenError::InvalidPDA,
            ZupyTokenError::DuplicateMemo,
            ZupyTokenError::InvalidMemoFormat,
            ZupyTokenError::NotInitialized,
            ZupyTokenError::InvalidMint,
            ZupyTokenError::ZeroAmount,
            ZupyTokenError::InvalidMetadataName,
            ZupyTokenError::InvalidMetadataSymbol,
            ZupyTokenError::InvalidMetadataUri,
            ZupyTokenError::ExtensionCalculationError,
            ZupyTokenError::InvalidPoolAccount,
            ZupyTokenError::SystemPaused,
            ZupyTokenError::UnauthorizedTreasury,
            ZupyTokenError::ExceedsTransactionLimit,
            ZupyTokenError::ExceedsDailyLimit,
            ZupyTokenError::InvalidTreasuryAccount,
            ZupyTokenError::InvalidIncentivePool,
            ZupyTokenError::InsufficientPoolBalance,
            ZupyTokenError::InvalidTokenProgram,
            ZupyTokenError::NotImplemented,
            ZupyTokenError::InvalidMetadataPDA,
            ZupyTokenError::InvalidOperationType,
            ZupyTokenError::SplitCalculationError,
        ];
        for error in errors {
            let code = error as u32;
            let pe: ProgramError = error.into();
            assert_eq!(pe, ProgramError::Custom(code));
        }
    }

    /// Verify contiguous range — no gaps in 6000..=6029
    #[test]
    fn test_error_codes_contiguous() {
        let all_codes: [u32; 30] = [
            ZupyTokenError::InvalidAuthority as u32,
            ZupyTokenError::DailyLimitExceeded as u32,
            ZupyTokenError::TxLimitExceeded as u32,
            ZupyTokenError::AlreadyInitialized as u32,
            ZupyTokenError::InsufficientBalance as u32,
            ZupyTokenError::InvalidAmount as u32,
            ZupyTokenError::RateLimitNotInitialized as u32,
            ZupyTokenError::InvalidPDA as u32,
            ZupyTokenError::DuplicateMemo as u32,
            ZupyTokenError::InvalidMemoFormat as u32,
            ZupyTokenError::NotInitialized as u32,
            ZupyTokenError::InvalidMint as u32,
            ZupyTokenError::ZeroAmount as u32,
            ZupyTokenError::InvalidMetadataName as u32,
            ZupyTokenError::InvalidMetadataSymbol as u32,
            ZupyTokenError::InvalidMetadataUri as u32,
            ZupyTokenError::ExtensionCalculationError as u32,
            ZupyTokenError::InvalidPoolAccount as u32,
            ZupyTokenError::SystemPaused as u32,
            ZupyTokenError::UnauthorizedTreasury as u32,
            ZupyTokenError::ExceedsTransactionLimit as u32,
            ZupyTokenError::ExceedsDailyLimit as u32,
            ZupyTokenError::InvalidTreasuryAccount as u32,
            ZupyTokenError::InvalidIncentivePool as u32,
            ZupyTokenError::InsufficientPoolBalance as u32,
            ZupyTokenError::InvalidTokenProgram as u32,
            ZupyTokenError::NotImplemented as u32,
            ZupyTokenError::InvalidMetadataPDA as u32,
            ZupyTokenError::InvalidOperationType as u32,
            ZupyTokenError::SplitCalculationError as u32,
        ];

        for (i, &code) in all_codes.iter().enumerate() {
            assert_eq!(code, 6000 + i as u32, "Gap at index {}", i);
        }
    }
}
