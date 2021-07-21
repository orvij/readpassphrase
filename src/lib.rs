extern crate readpassphrase_sys;

use std::ops::BitOr;

use readpassphrase_sys as ffi;

/// Flags argument able to bitwise OR zero or more flags
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u32)]
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

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct FlagsOr(u32);

impl From<Flags> for FlagsOr {
    fn from(f: Flags) -> Self {
        Self(f as u32)
    }
}

impl BitOr for Flags {
    type Output = FlagsOr;

    fn bitor(self, rhs: Self) -> Self::Output {
        FlagsOr((self as u32) | (rhs as u32))
    }
}

impl BitOr<Flags> for FlagsOr {
    type Output = FlagsOr;

    fn bitor(self, rhs: Flags) -> Self::Output {
        Self(self.0 | rhs as u32)
    }
}

impl BitOr for FlagsOr {
    type Output = FlagsOr;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl From<FlagsOr> for u32 {
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
///
/// let _pass = readpassphrase("Password:", 1024, Flags::RequireTty | Flags::ForceLower).unwrap();
/// ```
pub fn readpassphrase(prompt: &str, buf_len: usize, flags: FlagsOr) -> Result<String, Error> {
    let prompt_ptr = std::ffi::CString::new(prompt)?.into_raw();
    let buf = vec![1u8; buf_len];
    let buf_ptr = std::ffi::CString::new(buf)?.into_raw();
    // safety: all the pointers are non-null, and flags are valid
    // On failure a null pointer is returned
    let pass_ptr = unsafe { ffi::readpassphrase(prompt_ptr, buf_ptr, buf_len as i32, u32::from(flags) as i32) };

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
        // test that flags can be ORed together, and converted back to a Flag
        let mut or_flag: Flags = ((Flags::EchoOn as u32) | (Flags::RequireTty as u32)).into(); 
        assert_eq!(or_flag, Flags::EchoOnRequireTty);

        or_flag = ((Flags::EchoOn as u32) | (Flags::RequireTty as u32) | (Flags::ForceLower as u32)).into();
        assert_eq!(or_flag, Flags::EchoOnRequireTtyForceLower);

        or_flag = ((Flags::EchoOn as u32) | (Flags::RequireTty as u32) | (Flags::ForceUpper as u32)).into();
        assert_eq!(or_flag, Flags::EchoOnRequireTtyForceUpper);

        or_flag = ((Flags::EchoOn as u32) | (Flags::RequireTty as u32) | (Flags::ForceLower as u32) | (Flags::SevenBit as u32)).into();
        assert_eq!(or_flag, Flags::EchoOnRequireTtyForceLowerSevenBit);

        or_flag = ((Flags::EchoOn as u32) | (Flags::RequireTty as u32) | (Flags::ForceUpper as u32) | (Flags::SevenBit as u32)).into();
        assert_eq!(or_flag, Flags::EchoOnRequireTtyForceUpperSevenBit);

        or_flag = ((Flags::EchoOn as u32) | (Flags::RequireTty as u32) | (Flags::SevenBit as u32)).into();
        assert_eq!(or_flag, Flags::EchoOnRequireTtySevenBit);

        or_flag = ((Flags::EchoOn as u32) | (Flags::SevenBit as u32)).into();
        assert_eq!(or_flag, Flags::EchoOnSevenBit);

        or_flag = ((Flags::RequireTty as u32) | (Flags::ForceLower as u32)).into();
        assert_eq!(or_flag, Flags::RequireTtyForceLower);

        or_flag = ((Flags::RequireTty as u32) | (Flags::ForceUpper as u32)).into();
        assert_eq!(or_flag, Flags::RequireTtyForceUpper);

        or_flag = ((Flags::RequireTty as u32) | (Flags::ForceLower as u32) | (Flags::SevenBit as u32)).into();
        assert_eq!(or_flag, Flags::RequireTtyForceLowerSevenBit);

        or_flag = ((Flags::RequireTty as u32) | (Flags::ForceUpper as u32) | (Flags::SevenBit as u32)).into();
        assert_eq!(or_flag, Flags::RequireTtyForceUpperSevenBit);

        or_flag = ((Flags::RequireTty as u32) | (Flags::SevenBit as u32)).into();
        assert_eq!(or_flag, Flags::RequireTtySevenBit);
    }
}
