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

fn get_script_path() -> PathBuf {
    if let Ok(mut exe_path) = env::current_exe() {
        exe_path.pop();
        let script = exe_path.join("rustc-wrapper.sh");
        if script.exists() {
            return script;
        }
    }
    PathBuf::from("./.cargo/rustc-wrapper.sh")
}

fn main() {
    let bash_path = find_git_bash();
    let script_path = get_script_path();
    let args: Vec<String> = env::args().skip(1).collect();

    let status = Command::new(bash_path)
        .arg(script_path)
        .args(&args)
        .status()
        .expect("Failed to execute Git Bash wrapper");

    exit(status.code().unwrap_or(1));
}
