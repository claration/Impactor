use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{exit, Command};

fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dst.join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dst.join(entry.file_name()))?;
        }
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        exit(1);
    }

    let rustc_bin = &args[0];
    let rustc_args = &args[1..];

    let cargo_pkg_name = env::var("CARGO_PKG_NAME").ok();
    let cargo_manifest_dir = env::var("CARGO_MANIFEST_DIR").ok();

    if let (Some(pkg_name), Some(manifest_dir)) = (cargo_pkg_name, cargo_manifest_dir) {
        let manifest_path = Path::new(&manifest_dir);
        if let Some(dir_name) = manifest_path.file_name().and_then(|s| s.to_str()) {
            let root_dir = env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.to_path_buf()))
                .and_then(|p| p.parent().map(|p| p.to_path_buf()))
                .unwrap_or_else(|| PathBuf::from("."));

            let patch_dir = root_dir.join("patches").join(dir_name);

            if patch_dir.exists() && patch_dir.is_dir() {
                let patched_target = root_dir
                    .join("target")
                    .join("patched-crates")
                    .join(dir_name);

                let _ = fs::create_dir_all(patched_target.parent().unwrap());
                let _ = fs::remove_dir_all(&patched_target);

                if let Err(e) = copy_dir_all(manifest_path, &patched_target) {
                    eprintln!("Failed to copy source dir for patching: {e}");
                }

                if let Ok(entries) = fs::read_dir(&patch_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_file()
                            && path.extension().and_then(|s| s.to_str()) == Some("patch")
                        {
                            println!("Applying patch to {pkg_name}: {}", path.display());
                            let _ = Command::new("git")
                                .arg("apply")
                                .arg(format!("--directory={}", patched_target.display()))
                                .arg(&path)
                                .status();
                        }
                    }
                }

                let manifest_str = manifest_path.to_string_lossy().to_string();
                let patched_str = patched_target.to_string_lossy().to_string();

                let new_args: Vec<String> = rustc_args
                    .iter()
                    .map(|arg| arg.replace(&manifest_str, &patched_str))
                    .collect();

                let status = Command::new(rustc_bin)
                    .args(&new_args)
                    .status()
                    .expect("Failed to execute rustc");

                exit(status.code().unwrap_or(1));
            }
        }
    }

    let status = Command::new(rustc_bin)
        .args(rustc_args)
        .status()
        .expect("Failed to execute rustc");

    exit(status.code().unwrap_or(1));
}
