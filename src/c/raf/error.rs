use std::fmt;
use std::io::ErrorKind;

use super::errno::{EBADMSG, EOVERFLOW};

/// Errors returned by the random-access file (RAF) API.
#[derive(Debug)]
pub enum Error {
    /// An underlying I/O operation failed.
    Io(std::io::Error),
    /// A supplied argument or file header was invalid; the message gives details.
    InvalidArgument(&'static str),
    /// A chunk or header failed authentication: the data was tampered with, or
    /// the wrong key was used.
    AuthenticationFailed,
    /// The file already exists and creation was requested without truncation.
    AlreadyExists,
    /// The file does not exist.
    NotFound,
    /// An offset or size computation overflowed the addressable range.
    Overflow,
    /// A Merkle tree operation was requested on a file opened without one.
    MerkleNotEnabled,
    /// Merkle verification found a corrupted chunk, identified by its index.
    CorruptedChunk(u64),
    /// The random number generator failed to produce bytes.
    Rng,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {}", e),
            Error::InvalidArgument(s) => write!(f, "invalid argument: {}", s),
            Error::AuthenticationFailed => write!(f, "authentication failed"),
            Error::AlreadyExists => write!(f, "file already exists"),
            Error::NotFound => write!(f, "file not found"),
            Error::Overflow => write!(f, "overflow"),
            Error::MerkleNotEnabled => write!(f, "merkle tree not enabled"),
            Error::CorruptedChunk(idx) => write!(f, "corrupted chunk at index {}", idx),
            Error::Rng => write!(f, "random number generator error"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub(crate) fn map_errno_create() -> Error {
    let e = std::io::Error::last_os_error();
    match e.kind() {
        ErrorKind::InvalidInput => Error::InvalidArgument("invalid configuration"),
        ErrorKind::AlreadyExists => Error::AlreadyExists,
        ErrorKind::NotFound => Error::NotFound,
        _ => Error::Io(e),
    }
}

pub(crate) fn map_errno_open() -> Error {
    let e = std::io::Error::last_os_error();
    match e.raw_os_error() {
        Some(EBADMSG) => Error::AuthenticationFailed,
        Some(EOVERFLOW) => Error::Overflow,
        _ => match e.kind() {
            ErrorKind::InvalidInput => Error::InvalidArgument("invalid header or configuration"),
            ErrorKind::NotFound => Error::NotFound,
            _ => Error::Io(e),
        },
    }
}

pub(crate) fn map_errno_read() -> Error {
    let e = std::io::Error::last_os_error();
    match e.raw_os_error() {
        Some(EBADMSG) => Error::AuthenticationFailed,
        _ => match e.kind() {
            ErrorKind::InvalidInput => Error::InvalidArgument("invalid read parameters"),
            _ => Error::Io(e),
        },
    }
}

pub(crate) fn map_errno_write() -> Error {
    let e = std::io::Error::last_os_error();
    match e.raw_os_error() {
        Some(EOVERFLOW) => Error::Overflow,
        _ => match e.kind() {
            ErrorKind::InvalidInput => Error::InvalidArgument("invalid write parameters"),
            _ => Error::Io(e),
        },
    }
}

pub(crate) fn map_errno_truncate() -> Error {
    let e = std::io::Error::last_os_error();
    match e.kind() {
        ErrorKind::InvalidInput => Error::InvalidArgument("invalid truncate parameters"),
        _ => Error::Io(e),
    }
}

pub(crate) fn map_errno_merkle() -> Error {
    let e = std::io::Error::last_os_error();
    match e.raw_os_error() {
        Some(EBADMSG) => Error::AuthenticationFailed,
        _ => match e.kind() {
            ErrorKind::Unsupported => Error::MerkleNotEnabled,
            _ => Error::Io(e),
        },
    }
}

pub(crate) fn map_errno_probe() -> Error {
    let e = std::io::Error::last_os_error();
    match e.kind() {
        ErrorKind::InvalidInput => Error::InvalidArgument("invalid header"),
        _ => Error::Io(e),
    }
}
