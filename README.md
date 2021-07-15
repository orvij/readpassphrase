High level Rust API to OpenBSD's `readpassphrase` function.

From `man 3 readpassphrase`:

```
    The readpassphrase() function displays a prompt to, and reads in a
    passphrase from, /dev/tty.  If this file is inaccessible and the
    RPP_REQUIRE_TTY flag is not set, readpassphrase() displays the prompt on
    the standard error output and reads from the standard input.  In this
    case it is generally not possible to turn off echo.
    
    Up to bufsiz - 1 characters (one is for the NUL) are read into the
    provided buffer buf.  Any additional characters and the terminating
    newline (or return) character are discarded.
    
    The flags argument is the bitwise OR of zero or more of the following
    values:
    
          RPP_ECHO_OFF            turn off echo (default behavior)
          RPP_ECHO_ON             leave echo on
          RPP_REQUIRE_TTY         fail if there is no tty
          RPP_FORCELOWER          force input to lower case
          RPP_FORCEUPPER          force input to upper case
          RPP_SEVENBIT            strip the high bit from input
          RPP_STDIN               read passphrase from stdin; ignore prompt
```
