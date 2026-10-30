use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
#[cfg_attr(feature = "uniffi", uniffi(flat_error))]
pub enum Error {
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("http error: {0}")]
    Http(String),
    #[error("server returned {status}: {message}")]
    Server { status: u16, message: String },
    #[error("version conflict")]
    Conflict,
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("not found")]
    NotFound,
    #[error("io error: {0}")]
    Io(String),
    #[error("database error: {0}")]
    Db(String),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Invalid(e.to_string())
    }
}
