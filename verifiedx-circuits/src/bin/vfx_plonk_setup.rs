//! Generate PLONK params blob for VerifiedX.
//!
//! Usage:
//!   vfx_plonk_setup [--v0] [--verify-only] [output_path]
//!
//! Flags:
//!   --v0           Generate legacy VXPLNK01/02 format (v0 digest binding)
//!   --verify-only  Omit prover keys (smaller file, validator-only)
//!
//! Default: generates VXPLNK03 format with prover keys.
//!   Default output: vfx_plonk_v1.params (or vfx_plonk_v0.params for --v0)

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    let use_v0 = args.iter().any(|a| a == "--v0");
    let verify_only = args.iter().any(|a| a == "--verify-only");

    // Find the output path (first arg that doesn't start with --)
    let out: PathBuf = args
        .iter()
        .skip(1)
        .find(|a| !a.starts_with("--"))
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            if use_v0 {
                PathBuf::from("vfx_plonk_v0.params")
            } else {
                PathBuf::from("vfx_plonk_v1.params")
            }
        });

    if use_v0 {
        // Legacy v0 format
        let blob = verifiedx_circuits::trusted_setup_v0()?;
        let bytes = blob.serialize()?;
        fs::write(&out, &bytes)?;
        eprintln!(
            "Wrote {} bytes to {} (VXPLNK01 v0 PI-digest binding).",
            bytes.len(),
            out.display()
        );
    } else {
        // v1 format with real circuits
        let include_pk = !verify_only;
        eprintln!("Compiling v1 circuits (Shield, Transfer, Unshield, Fee)...");
        eprintln!("  Include prover keys: {}", include_pk);
        eprintln!("  This may take a few minutes...");

        let blob = verifiedx_circuits::trusted_setup_v1(include_pk)?;
        let bytes = blob.serialize();
        fs::write(&out, &bytes)?;
        eprintln!(
            "Wrote {} bytes to {} (VXPLNK03 v1 real circuits, {} prover keys).",
            bytes.len(),
            out.display(),
            if include_pk { "with" } else { "without" }
        );
    }

    Ok(())
}