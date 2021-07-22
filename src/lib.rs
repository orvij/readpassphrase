extern crate readpassphrase_sys;

use std::ops::BitOr;

use readpassphrase_sys as ffi;

/// Flags argument able to bitwise OR zero or more flags
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(i32)]
pub enum Flags {
    /// Turn off echo (default behavior)
    EchoOff = ffi::RPP_ECHO_OFF,
    /// Leave echo on
    EchoOn = ffi::RPP_ECHO_ON,
    /// Fail if there is no TTY
    RequireTty = ffi::RPP_REQUIRE_TTY,
    /// Force input to lower case
    ForceLower = ffi::RPP_FORCELOWER,
    /// Force input to upper case
    ForceUpper = ffi::RPP_FORCEUPPER,
    /// Strip the high bit from input
    SevenBit = ffi::RPP_SEVENBIT,
    /// Read passphrase from stdin; ignore prompt
    StdIn = ffi::RPP_STDIN,
}

/// Wrapper type for bitwise OR-ed flags
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct FlagsOr(i32);

impl From<Flags> for FlagsOr {
    fn from(f: Flags) -> Self {
        Self(f as i32)
    }
}

impl BitOr for Flags {
    type Output = FlagsOr;

    fn bitor(self, rhs: Self) -> Self::Output {
        FlagsOr((self as i32) | (rhs as i32))
    }
}

impl BitOr<Flags> for FlagsOr {
    type Output = FlagsOr;

    fn bitor(self, rhs: Flags) -> Self::Output {
        Self(self.0 | rhs as i32)
    }
}

impl BitOr for FlagsOr {
    type Output = FlagsOr;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl From<FlagsOr> for i32 {
    fn from(f: FlagsOr) -> Self {
        f.0
    }
}

/// Error type indicating a failed call to readpassphrase
#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    General,
    Utf8(std::str::Utf8Error),
    Nul(std::ffi::NulError),
}

impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Self {
        Self::Utf8(e)
    }
}

impl From<std::ffi::NulError> for Error {
    fn from(e: std::ffi::NulError) -> Self {
        Self::Nul(e)
    }
}

/// Displays a prompt to, and reads in a passphrase from, /dev/tty
/// 
/// If this file is inaccessible and the RPP_REQUIRE_TTY flag is not set,
/// readpassphrase displays the prompt on the standard error output and
/// reads from the standard input. In this case it is generally not possible
/// to turn off echo.
///
/// Example:
///
/// ```rust,no_run
/// # use readpassphrase::{readpassphrase, Flags};
/// let _pass = readpassphrase("Password:", 1024, Flags::RequireTty.into()).unwrap();
/// /* or */
/// let _pass = readpassphrase("Password:", 1024, Flags::RequireTty | Flags::ForceLower).unwrap();
/// ```
pub fn readpassphrase(prompt: &str, buf_len: usize, flags: FlagsOr) -> Result<String, Error> {
    let prompt_ptr = std::ffi::CString::new(prompt)?.into_raw();
    let buf = vec![1u8; buf_len];
    let buf_ptr = std::ffi::CString::new(buf)?.into_raw();
    // safety: all the pointers are non-null, and flags are valid
    // On failure a null pointer is returned
    let pass_ptr = unsafe { ffi::readpassphrase(prompt_ptr, buf_ptr, buf_len, flags.into()) };

    if pass_ptr == std::ptr::null_mut() {
        // safety: buf is non-null, and points to valid memory
        unsafe { libc::explicit_bzero(buf_ptr as *mut _, buf_len) };
        Err(Error::General)
    } else {
        // safety: pass_ptr is a pointer to valid memory, even if it not
        // a valid UTF8 C-string
        let pass_cstr = unsafe { std::ffi::CString::from_raw(pass_ptr) };
        let pass_len = pass_cstr.as_bytes().len();

        let pass = match pass_cstr.to_str() {
            Ok(p) => Ok(p.to_string()),
            Err(_) => Err(Error::General),
        };

        // clear the returned passphrase buffer
        // safety: pass and buf pointers are non-null, and point to valid memory
        unsafe { 
            libc::explicit_bzero(pass_ptr as *mut _, pass_len);
            libc::explicit_bzero(buf_ptr as *mut _, buf_len);
        }

        pass
    }
}

/// Convenience function to securely clear a passphrase
///
/// Example:
///
/// ```rust
/// # use readpassphrase::clear_passphrase;
/// let mut passphrase = "super secret password".to_string();
/// clear_passphrase(&mut passphrase);
/// assert_eq!(passphrase.as_bytes(), [0; 21].as_ref());
/// ```
pub fn clear_passphrase(pass: &mut str) {
    let ptr = pass.as_mut_ptr();
    // safety: pass pointer is non-null, and points to valid memory
    unsafe { libc::explicit_bzero(ptr as *mut _, pass.len()) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flags() {
        let orflags = Flags::RequireTty | Flags::SevenBit;
        assert_eq!(orflags.0, (Flags::RequireTty as i32) | (Flags::SevenBit as i32));
    }
}
