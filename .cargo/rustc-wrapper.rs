use std::env;
use std::process::{exit, Command};

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let status = Command::new("bash")
        .arg("./.cargo/rustc-wrapper.sh")
        .args(&args)
        .status()
        .expect("Failed to execute Git Bash wrapper");

    exit(status.code().unwrap_or(1));
}
