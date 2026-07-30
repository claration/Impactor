use anyhow::Result;
use clap::Args;
use plume_core::{MachO, MachOExt};
use std::path::PathBuf;

#[derive(Debug, Args)]
#[command(arg_required_else_help = true)]
pub struct MachArgs {
    #[arg(value_name = "BINARY")]
    pub binary: PathBuf,
    #[arg(long)]
    pub entitlements: bool,
    /// List all dylib dependencies
    #[arg(long)]
    pub list_dylibs: bool,
    /// Add a dylib dependency (e.g., @rpath/MyLib.dylib)
    #[arg(long, value_name = "DYLIB_PATH")]
    pub add_dylib: Option<String>,
    /// List all LC_RPATH search paths
    #[arg(long)]
    pub list_rpaths: bool,
    /// Add an LC_RPATH search path
    #[arg(long, value_name = "RPATH")]
    pub add_rpath: Option<String>,
    /// Replace an existing dylib dependency
    #[arg(long, value_names = &["OLD", "NEW"], num_args = 2)]
    pub replace_dylib: Option<Vec<String>>,
    /// Set the SDK version (e.g., 26.0.0)
    #[arg(long, value_name = "SDK_VERSION")]
    pub sdk_version: Option<String>,
}

pub async fn execute(args: MachArgs) -> Result<()> {
    let mut macho = MachO::new(&args.binary)?;

    if let Some(dylib_path) = &args.add_dylib {
        macho.add_dylib(dylib_path)?;
        return Ok(());
    }

    if let Some(rpath) = &args.add_rpath {
        macho.add_rpath(rpath)?;
        return Ok(());
    }

    if let Some(replace_paths) = &args.replace_dylib {
        if replace_paths.len() == 2 {
            macho.replace_dylib(&replace_paths[0], &replace_paths[1])?;
            return Ok(());
        }
    }

    if args.list_dylibs {
        // TODO: add index argument
        let d = macho
            .macho_file()
            .nth_macho(0)
            .unwrap()
            .dylib_load_paths()
            .unwrap();
        for path in d {
            println!("{path}");
        }
        return Ok(());
    }

    if args.list_rpaths {
        for path in macho.rpaths()? {
            println!("{path}");
        }
        return Ok(());
    }

    if let Some(sdk_version) = &args.sdk_version {
        macho.replace_sdk_version(sdk_version)?;
        return Ok(());
    }

    let entitlements = macho.entitlements();
    if args.entitlements {
        if let Some(ent) = entitlements {
            let mut buf = Vec::new();
            plist::Value::Dictionary(ent.clone()).to_writer_xml(&mut buf)?;
            let xml_str = String::from_utf8(buf)?;
            println!("{}", xml_str);
        }
    }

    Ok(())
}
