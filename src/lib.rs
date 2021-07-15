extern crate readpassphrase_sys;

use readpassphrase_sys as ffi;

const REQUIRE_TTY_FORCE_LOWER: u32 = ffi::RPP_REQUIRE_TTY | ffi::RPP_FORCELOWER;
const REQUIRE_TTY_FORCE_LOWER_SEVENBIT: u32 = ffi::RPP_REQUIRE_TTY | ffi::RPP_FORCELOWER | ffi::RPP_SEVENBIT;
const REQUIRE_TTY_FORCE_UPPER: u32 = ffi::RPP_REQUIRE_TTY | ffi::RPP_FORCEUPPER;
const REQUIRE_TTY_FORCE_UPPER_SEVENBIT: u32 = ffi::RPP_REQUIRE_TTY | ffi::RPP_FORCEUPPER | ffi::RPP_SEVENBIT;
const REQUIRE_TTY_SEVENBIT: u32 = ffi::RPP_REQUIRE_TTY | ffi::RPP_SEVENBIT;
const ECHO_ON_REQUIRE_TTY: u32 = ffi::RPP_ECHO_ON | ffi::RPP_REQUIRE_TTY;
const ECHO_ON_REQUIRE_TTY_FORCE_LOWER: u32 = ffi::RPP_ECHO_ON | ffi::RPP_REQUIRE_TTY | ffi::RPP_FORCELOWER;
const ECHO_ON_REQUIRE_TTY_FORCE_LOWER_SEVENBIT: u32 = ffi::RPP_ECHO_ON | ffi::RPP_REQUIRE_TTY | ffi::RPP_FORCELOWER | ffi::RPP_SEVENBIT;
const ECHO_ON_REQUIRE_TTY_FORCE_UPPER: u32 = ffi::RPP_ECHO_ON | ffi::RPP_REQUIRE_TTY | ffi::RPP_FORCEUPPER;
const ECHO_ON_REQUIRE_TTY_FORCE_UPPER_SEVENBIT: u32 = ffi::RPP_ECHO_ON | ffi::RPP_REQUIRE_TTY | ffi::RPP_FORCEUPPER | ffi::RPP_SEVENBIT;
const ECHO_ON_REQUIRE_TTY_SEVENBIT: u32 = ffi::RPP_ECHO_ON | ffi::RPP_REQUIRE_TTY | ffi::RPP_SEVENBIT;
const ECHO_ON_SEVENBIT: u32 = ffi::RPP_ECHO_ON | ffi::RPP_SEVENBIT;
const STDIN_FORCE_LOWER: u32 = ffi::RPP_STDIN | ffi::RPP_FORCELOWER;
const STDIN_FORCE_LOWER_SEVENBIT: u32 = ffi::RPP_STDIN | ffi::RPP_FORCELOWER | ffi::RPP_SEVENBIT;
const STDIN_FORCE_UPPER: u32 = ffi::RPP_STDIN | ffi::RPP_FORCEUPPER;
const STDIN_FORCE_UPPER_SEVENBIT: u32 = ffi::RPP_STDIN | ffi::RPP_FORCEUPPER | ffi::RPP_SEVENBIT;
const STDIN_SEVENBIT: u32 = ffi::RPP_STDIN | ffi::RPP_SEVENBIT;

/// Flags argument able to bitwise OR zero or more flags
#[derive(Debug, Eq, PartialEq)]
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
    /// Turn echo off, require TTY, and force input to lower case
    RequireTtyForceLower = ffi::RPP_REQUIRE_TTY | ffi::RPP_FORCELOWER,
    /// Turn echo off, require TTY, and force input to upper case
    RequireTtyForceUpper = ffi::RPP_REQUIRE_TTY | ffi::RPP_FORCEUPPER,
    /// Turn echo off, require TTY, force input to lower case, and strip high bit from input
    RequireTtyForceLowerSevenBit = ffi::RPP_REQUIRE_TTY | ffi::RPP_FORCELOWER | ffi::RPP_SEVENBIT,
    /// Turn echo off, require TTY, force input to upper case, and strip high bit from input
    RequireTtyForceUpperSevenBit = ffi::RPP_REQUIRE_TTY | ffi::RPP_FORCEUPPER | ffi::RPP_SEVENBIT,
    /// Turn echo off, require TTY, and strip high bit from input
    RequireTtySevenBit = ffi::RPP_REQUIRE_TTY | ffi::RPP_SEVENBIT,
    EchoOnRequireTty = ffi::RPP_ECHO_ON | ffi::RPP_REQUIRE_TTY,
    /// Turn echo on, require TTY, and force input to lower case
    EchoOnRequireTtyForceLower = ffi::RPP_ECHO_ON | ffi::RPP_REQUIRE_TTY | ffi::RPP_FORCELOWER,
    /// Turn echo on, require TTY, and force input to upper case
    EchoOnRequireTtyForceUpper = ffi::RPP_ECHO_ON | ffi::RPP_REQUIRE_TTY | ffi::RPP_FORCEUPPER,
    /// Turn echo on, require TTY, force input to lower case, and strip high bit from input
    EchoOnRequireTtyForceLowerSevenBit = ffi::RPP_ECHO_ON | ffi::RPP_REQUIRE_TTY | ffi::RPP_FORCELOWER | ffi::RPP_SEVENBIT,
    /// Turn echo on, require TTY, force input to upper case, and strip high bit from input
    EchoOnRequireTtyForceUpperSevenBit = ffi::RPP_ECHO_ON | ffi::RPP_REQUIRE_TTY | ffi::RPP_FORCEUPPER | ffi::RPP_SEVENBIT,
    /// Turn echo on, require TTY, and strip high bit from input
    EchoOnRequireTtySevenBit = ffi::RPP_ECHO_ON | ffi::RPP_REQUIRE_TTY | ffi::RPP_SEVENBIT,
    /// Turn echo on and strip high bit from input
    EchoOnSevenBit = ffi::RPP_ECHO_ON | ffi::RPP_SEVENBIT,
    /// Use stdin and force input to lower case
    StdInForceLower = ffi::RPP_STDIN | ffi::RPP_FORCELOWER,
    /// Use stdin and force input to upper case
    StdInForceUpper = ffi::RPP_STDIN | ffi::RPP_FORCEUPPER,
    /// Use stdin and strip high bit from input
    StdInSevenBit = ffi::RPP_STDIN | ffi::RPP_SEVENBIT,
    /// Use stdin, for input to lower case, and strip high bit from input
    StdInForceLowerSevenBit = ffi::RPP_STDIN | ffi::RPP_FORCELOWER | ffi::RPP_SEVENBIT,
    /// Use stdin, for input to upper case, and strip high bit from input
    StdInForceUpperSevenBit = ffi::RPP_STDIN | ffi::RPP_FORCEUPPER | ffi::RPP_SEVENBIT,
}

impl From<u32> for Flags {
    fn from(f: u32) -> Self {
        match f {
            REQUIRE_TTY_FORCE_LOWER => Self::RequireTtyForceLower,
            REQUIRE_TTY_FORCE_LOWER_SEVENBIT => Self::RequireTtyForceLowerSevenBit,
            REQUIRE_TTY_FORCE_UPPER => Self::RequireTtyForceUpper,
            REQUIRE_TTY_FORCE_UPPER_SEVENBIT => Self::RequireTtyForceUpperSevenBit,
            REQUIRE_TTY_SEVENBIT => Self::RequireTtySevenBit,
            ECHO_ON_REQUIRE_TTY => Self::EchoOnRequireTty,
            ECHO_ON_REQUIRE_TTY_FORCE_LOWER => Self::EchoOnRequireTtyForceLower,
            ECHO_ON_REQUIRE_TTY_FORCE_LOWER_SEVENBIT => Self::EchoOnRequireTtyForceLowerSevenBit,
            ECHO_ON_REQUIRE_TTY_FORCE_UPPER => Self::EchoOnRequireTtyForceUpper,
            ECHO_ON_REQUIRE_TTY_FORCE_UPPER_SEVENBIT => Self::EchoOnRequireTtyForceUpperSevenBit,
            ECHO_ON_REQUIRE_TTY_SEVENBIT => Self::EchoOnRequireTtySevenBit,
            ECHO_ON_SEVENBIT => Self::EchoOnSevenBit,
            STDIN_FORCE_LOWER => Self::StdInForceLower,
            STDIN_FORCE_LOWER_SEVENBIT => Self::StdInForceLowerSevenBit,
            STDIN_FORCE_UPPER => Self::StdInForceUpper,
            STDIN_FORCE_UPPER_SEVENBIT => Self::StdInForceUpperSevenBit,
            STDIN_SEVENBIT => Self::StdInSevenBit,
            _ => panic!("invalid flag: {}", f),
        }
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
pub fn readpassphrase(prompt: &str, buf_len: usize, flags: Flags) -> Result<String, Error> {
    let prompt_ptr = std::ffi::CString::new(prompt)?.into_raw();
    let buf = vec![1u8; buf_len];
    let buf_ptr = std::ffi::CString::new(buf)?.into_raw();
    // safety: all the pointers are non-null, and flags are valid
    // On failure a null pointer is returned
    let pass_ptr = unsafe { ffi::readpassphrase(prompt_ptr, buf_ptr, buf_len as i32, flags as u32 as i32) };

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
