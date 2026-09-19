use std::env;
use std::path::PathBuf;
use std::process::{exit, Command};

fn find_git_bash() -> PathBuf {
    let candidates = [
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
        r"C:\Program Files (x86)\Git\bin\bash.exe",
    ];

    for path in &candidates {
        let p = PathBuf::from(path);
        if p.exists() {
            return p;
        }
    }

    if let Ok(program_files) = env::var("ProgramFiles") {
        let p = PathBuf::from(program_files).join(r"Git\bin\bash.exe");
        if p.exists() {
            return p;
        }
    }

    PathBuf::from("bash")
}

fn main() {
    let bash_path = find_git_bash();
    let args: Vec<String> = env::args().skip(1).collect();
    let status = Command::new(bash_path)
        .arg("./.cargo/rustc-wrapper.sh")
        .args(&args)
        .status()
        .expect("Failed to execute Git Bash wrapper");

    exit(status.code().unwrap_or(1));
}
