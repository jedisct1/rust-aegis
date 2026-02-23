pub const EIO: i32 = 5;

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "emscripten",
    target_os = "wasi"
))]
pub const EBADMSG: i32 = 74;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos"
))]
pub const EBADMSG: i32 = 94;
#[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
pub const EBADMSG: i32 = 89;
#[cfg(target_os = "openbsd")]
pub const EBADMSG: i32 = 92;
#[cfg(target_os = "netbsd")]
pub const EBADMSG: i32 = 88;

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "emscripten",
    target_os = "wasi"
))]
pub const EOVERFLOW: i32 = 75;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
))]
pub const EOVERFLOW: i32 = 84;
#[cfg(target_os = "openbsd")]
pub const EOVERFLOW: i32 = 87;

pub fn set_errno(code: i32) {
    unsafe { *errno_ptr() = code }
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "emscripten",
    target_os = "wasi"
))]
unsafe fn errno_ptr() -> *mut i32 {
    extern "C" {
        fn __errno_location() -> *mut i32;
    }
    unsafe { __errno_location() }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "freebsd",
    target_os = "dragonfly",
))]
unsafe fn errno_ptr() -> *mut i32 {
    extern "C" {
        fn __error() -> *mut i32;
    }
    unsafe { __error() }
}

#[cfg(any(target_os = "openbsd", target_os = "netbsd"))]
unsafe fn errno_ptr() -> *mut i32 {
    extern "C" {
        fn __errno() -> *mut i32;
    }
    unsafe { __errno() }
}

#[cfg(target_os = "windows")]
unsafe fn errno_ptr() -> *mut i32 {
    extern "C" {
        fn _errno() -> *mut i32;
    }
    unsafe { _errno() }
}
