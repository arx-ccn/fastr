use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("pack error: {0}")]
    Pack(#[from] PackError),

    #[error("invalid event: {0}")]
    InvalidEvent(&'static str),

    #[error("invalid signature")]
    InvalidSignature,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("duplicate event")]
    Duplicate,

    #[error("{0}")]
    Rejected(&'static str),
}

#[derive(Debug, Error)]
pub enum PackError {
    #[error("buffer too small")]
    BufferTooSmall,

    #[error("invalid data")]
    Invalid,

    #[error("invalid hex")]
    InvalidHex,

    #[error("varint overflow")]
    VarintOverflow,

    #[error("tag count exceeds limit")]
    TooManyTags,

    #[error("content exceeds limit")]
    ContentTooLarge,
}
