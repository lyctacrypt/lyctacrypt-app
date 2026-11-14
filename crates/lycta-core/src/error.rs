use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("cryptographic failure")]
    Crypto,
    #[error("malformed data")]
    Malformed,
    #[error("invalid invite")]
    BadInvite,
    #[error("wrong passphrase or corrupted vault")]
    VaultDecrypt,
    #[error("this vault requires its original TPM-bound key")]
    DeviceBoundVault,
    #[error("too many skipped messages")]
    TooManySkipped,
    #[error("no sending chain yet")]
    NoSendingChain,
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<bincode::Error> for Error {
    fn from(_: bincode::Error) -> Self {
        Error::Malformed
    }
}
