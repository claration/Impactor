// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use apple_codesign::AppleCodesignError;

fn main() {
    let exit_code = match apple_codesign::cli::main_impl() {
        Ok(()) => 0,
        Err(AppleCodesignError::Figment(err)) => {
            eprintln!("configuration file error");

            err.metadata.as_ref().map(|metadata| {
                metadata.source.as_ref().map(|source| {
                    source.file_path().map(|path| {
                        eprintln!("  source path: {}", path.display());
                    })
                })
            });
            if let Some(profile) = err.profile.as_ref() { eprintln!("  in profile: {}", profile) }
            eprintln!("  problem key: {}", err.path.join(", "));
            eprintln!("  problem: {:?}", err.kind);

            1
        }
        Err(err) => {
            eprintln!("Error: {err}");
            1
        }
    };

    std::process::exit(exit_code)
}
