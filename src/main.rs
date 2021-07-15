use readpassphrase::{clear_passphrase, readpassphrase, Flags};

// Test program to ensure readpassphrase is working correctly
fn main() {
    let prompt = "Enter passphrase: ";
    let mut passphrase = readpassphrase(prompt, 1024, Flags::RequireTty).expect("failed to read passphrase from /dev/tty");
    println!("You entered: {}", passphrase);

    // clear the passphrase
    clear_passphrase(passphrase.as_mut_str());
}
