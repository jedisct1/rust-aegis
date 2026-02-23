use std::fmt;
use std::io::ErrorKind;

use super::errno::{EBADMSG, EOVERFLOW};

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    InvalidArgument(&'static str),
    AuthenticationFailed,
    AlreadyExists,
    NotFound,
    Overflow,
    MerkleNotEnabled,
    CorruptedChunk(u64),
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
