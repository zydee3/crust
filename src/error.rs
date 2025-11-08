use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CrustError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Protobuf decode error: {0}")]
    ProtobufDecode(#[from] prost::DecodeError),

    #[error("Image file not found: {path}")]
    ImageNotFound { path: String },

    #[error("Invalid image format: {reason}")]
    InvalidImage { reason: String },

    #[error("PID control failed: {0}")]
    PidControl(String),
}

pub type Result<T> = std::result::Result<T, CrustError>;
