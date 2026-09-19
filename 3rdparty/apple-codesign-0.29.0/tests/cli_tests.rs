// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use {
    anyhow::anyhow,
    reqwest::Url,
    std::{
        io::Read,
        path::{Path, PathBuf},
    },
    trycmd_indygreg_fork::{schema::TryCmd, Error, TestCases},
};

const COREUTILS_VERSION: &str = "0.0.22";
/// List of coreutils binaries to materialize in trycmd test environments.
const COREUTILS_BINARIES: [&str; 11] = [
    "cat", "cp", "hashsum", "ln", "ls", "mkdir", "mv", "rm", "sort", "test", "touch",
];

const COREUTILS_ARTIFACT_URL: &str = "https://github.com/uutils/coreutils/releases/download";
const COREUTILS_TAR_TRIPLES: [&str; 4] = [
    "aarch64-unknown-linux-gnu",
    "i686-unknown-linux-musl",
    "x86_64-apple-darwin",
    "x86_64-unknown-linux-musl",
];

const COREUTILS_ZIP_TRIPLES: [&str; 2] = ["i686-pc-windows-msvc", "x86_64-pc-windows-msvc"];

/// Ensures Rust coreutils multicall binary is available.
///
/// Essentially runs `cargo install coreutils` into the `target/coreutils` directory
/// for the current Cargo workspace project.
fn ensure_coreutils_multicall() -> anyhow::Result<PathBuf> {
    let current_exe = std::env::current_exe()?;

    let target_dir = current_exe
        .parent()
        .ok_or_else(|| anyhow!("unable to determine current exe parent"))?
        .parent()
        .ok_or_else(|| anyhow!("unable to determine parent directory of current exe directory"))?
        .parent()
        .ok_or_else(|| anyhow!("unable to parent grandparent of current exe directory"))?;

    let coreutils_dir = target_dir.join("coreutils");

    let coreutils_bin_dir = coreutils_dir.join("bin");

    let multicall_bin = coreutils_bin_dir.join("coreutils");

    let multicall_bin = materialize_coreutils(&coreutils_dir, &multicall_bin)?;

    Ok(multicall_bin)
}

fn materialize_coreutils(coreutils_dir: &Path, multicall_bin: &Path) -> anyhow::Result<PathBuf> {
    let triple = if cfg!(all(target_os = "linux", target_arch = "x86")) {
        Some("i686-unknown-linux-musl")
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Some("x86_64-unknown-linux-musl")
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        Some("x86_64-apple-darwin")
    } else if cfg!(all(target_os = "windows", target_arch = "x86")) {
        Some("i686-pc-windows-msvc")
    } else if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        Some("x86_64-pc-windows-msvc")
    } else {
        None
    };

    let mut multicall_bin = multicall_bin.to_path_buf();

    if let Some(triple) = triple {
        if triple.contains("-windows-") {
            multicall_bin.set_extension("exe");
        }
    }

    if multicall_bin.exists() {
        return Ok(multicall_bin);
    }

    match triple {
        Some(triple) => {
            let suffix = if COREUTILS_TAR_TRIPLES.contains(&triple) {
                "tar.gz"
            } else if COREUTILS_ZIP_TRIPLES.contains(&triple) {
                "zip"
            } else {
                panic!("unhandled triple")
            };

            let filename = multicall_bin
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string();

            let exe_data = download_coreutils_artifact(triple, suffix, &filename)?;
            eprintln!("writing {}", multicall_bin.display());

            if let Some(parent) = multicall_bin.parent() {
                std::fs::create_dir_all(parent)?;
            }

            std::fs::write(&multicall_bin, exe_data)?;
            simple_file_manifest::set_executable(&mut std::fs::File::open(&multicall_bin)?)?;

            Ok(multicall_bin)
        }
        None => {
            let cargo_bin = std::env::var_os("CARGO")
                .ok_or_else(|| anyhow!("unable to resolve CARGO environment variable"))?;

            eprintln!("installing Rust coreutils to {}", coreutils_dir.display());
            let output = std::process::Command::new(cargo_bin)
                .args(vec![
                    "install".to_string(),
                    "--root".to_string(),
                    coreutils_dir.display().to_string(),
                    "--version".to_string(),
                    COREUTILS_VERSION.to_string(),
                    "coreutils".to_string(),
                ])
                .output()?;

            if !output.status.success() {
                return Err(anyhow!(
                    "error installing coreutils: stdout: {}; stderr: {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                ));
            }

            Ok(multicall_bin)
        }
    }
}

fn download_coreutils_artifact(
    triple: &str,
    suffix: &str,
    multicall_filename: &str,
) -> anyhow::Result<Vec<u8>> {
    let url = format!("{COREUTILS_ARTIFACT_URL}/{COREUTILS_VERSION}/coreutils-{COREUTILS_VERSION}-{triple}.{suffix}");

    let client = get_http_client()?;
    eprintln!("downloading {}", url);
    let mut res = client.get(url).send()?;
    let mut data = vec![];
    res.read_to_end(&mut data)?;

    match suffix {
        "tar.gz" => {
            eprintln!("looking for {} in tar.gz", multicall_filename);
            let d = flate2::read::GzDecoder::new(std::io::Cursor::new(data));

            let mut ar = tar::Archive::new(d);

            for entry in ar.entries()? {
                let mut entry = entry?;
                let path = entry.path()?;

                if !path.display().to_string().ends_with(multicall_filename) {
                    continue;
                }

                eprintln!("extracting {} from tar.gz", path.display());
                let mut buf = vec![];
                entry.read_to_end(&mut buf)?;

                return Ok(buf);
            }

            Err(anyhow!("could not find multicall binary in archive"))
        }
        "zip" => {
            eprintln!("looking for {} in zip file", multicall_filename);
            let mut archive = zip::ZipArchive::new(std::io::Cursor::new(data))?;

            let archive_name = archive
                .file_names()
                .find(|f| f.ends_with(multicall_filename))
                .ok_or_else(|| anyhow!("could not find multicall binary in zip file"))?
                .to_string();

            eprintln!("extracting {} from zip file", archive_name);
            let mut zf = archive.by_name(&archive_name)?;
            let mut buf = vec![];
            zf.read_to_end(&mut buf)?;

            Ok(buf)
        }
        _ => panic!("unhandled coreutils file extension"),
    }
}

pub fn get_http_client() -> reqwest::Result<reqwest::blocking::Client> {
    let mut builder = reqwest::blocking::ClientBuilder::new();

    for (key, value) in std::env::vars() {
        let key = key.to_lowercase();
        if key.ends_with("_proxy") {
            let end = key.len() - "_proxy".len();
            let schema = &key[..end];

            if let Ok(url) = Url::parse(&value) {
                if let Some(Ok(proxy)) = match schema {
                    "http" => Some(reqwest::Proxy::http(url.as_str())),
                    "https" => Some(reqwest::Proxy::https(url.as_str())),
                    _ => None,
                } {
                    builder = builder.proxy(proxy);
                }
            }
        }
    }

    builder.build()
}

#[cfg(unix)]
fn install_coreutils_bin(multicall_bin: &Path, bin: &Path) -> Result<(), std::io::Error> {
    std::os::unix::fs::symlink(multicall_bin, bin)
}

#[cfg(windows)]
fn install_coreutils_bin(multicall_bin: &Path, bin: &Path) -> Result<(), std::io::Error> {
    std::fs::copy(multicall_bin, bin).map(|_| ())
}

/// Custom loader for .trycmd files.
fn load_trycmd(path: &Path) -> Result<TryCmd, Error> {
    let mut cmd = TryCmd::load_trycmd(path)?;

    // CWD should be the crate root.
    let cwd = std::env::current_dir().map_err(Error::new)?;

    // We set the test to execute from a sandboxed copy of the crate root.
    // This allows tests to create their own files without disturbing the
    // source checkout.
    cmd.fs.base = Some(cwd.clone());
    cmd.fs.cwd = Some(cwd.clone());
    cmd.fs.sandbox = Some(true);

    Ok(cmd)
}

#[test]
fn cli_tests() {
    let coreutils_multicall = ensure_coreutils_multicall().unwrap();
    let coreutils_bin = coreutils_multicall.parent().unwrap();

    let cases = TestCases::new();

    for bin in COREUTILS_BINARIES {
        let mut bin_path = coreutils_bin.join(bin);
        if cfg!(windows) {
            bin_path.set_extension("exe");
        }

        if bin_path.symlink_metadata().is_err() {
            install_coreutils_bin(&coreutils_multicall, &bin_path).unwrap();
        }

        cases.register_bin(bin, bin_path);
    }

    cases.file_extension_loader("trycmd", load_trycmd);

    cases.case("tests/cmd/*.trycmd").case("tests/cmd/*.toml");

    // Help output breaks without notarize feature.
    if cfg!(not(feature = "notarize")) {
        cases.skip("tests/cmd/encode-app-store-connect-api-key.trycmd");
        cases.skip("tests/cmd/help.trycmd");
        cases.skip("tests/cmd/notary*.trycmd");
    }

    // Tests with `ln -s` may not work on Windows. So just skip them.
    if cfg!(windows) {
        cases.skip("tests/cmd/sign-bundle-framework.trycmd");
        cases.skip("tests/cmd/sign-bundle-with-nested-framework.trycmd");
        cases.skip("tests/cmd/sign-bundle-electron.trycmd");
        cases.skip("tests/cmd/sign-bundle-exclude.trycmd");
        cases.skip("tests/cmd/sign-bundle-nested-symlinks.trycmd");
        cases.skip("tests/cmd/sign-bundle-symlink-overwrite.trycmd");
    }
}
