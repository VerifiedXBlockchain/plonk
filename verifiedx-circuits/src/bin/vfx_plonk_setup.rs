//! Generate PLONK params blob for VerifiedX.
//!
//! Usage:
//!   vfx_plonk_setup [--v0] [--verify-only] [output_path]
//!
//! Flags:
//!   --v0           Generate legacy VXPLNK01/02 format (v0 digest binding)
//!   --verify-only  Omit prover keys (smaller file, validator-only)
//!
//! Default (`--zcash <phase1radix>`): VXPLNK06, v2 owner-bound circuits over the Zcash Powers of Tau.
//! `--insecure-seeded`: VXPLNK04 from the seeded setup (tests only; the node refuses it).
//!   Default output: vfx_plonk_v1.params (or vfx_plonk_v0.params for --v0)

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    let use_v0 = args.iter().any(|a| a == "--v0");
    let verify_only = args.iter().any(|a| a == "--verify-only");
    let insecure_seeded = args.iter().any(|a| a == "--insecure-seeded");
    let zcash: Option<PathBuf> = args.iter().position(|a| a == "--zcash").and_then(|i| args.get(i + 1)).map(PathBuf::from);

    // Find the output path (first positional arg; the --zcash value is not one)
    let zcash_str = zcash.as_ref().map(|p| p.to_string_lossy().into_owned());
    let out: PathBuf = args
        .iter()
        .skip(1)
        .find(|a| !a.starts_with("--") && Some(a.as_str()) != zcash_str.as_deref())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            if use_v0 {
                PathBuf::from("vfx_plonk_v0.params")
            } else if zcash.is_some() {
                PathBuf::from("vfx_plonk_v4.params")
            } else {
                PathBuf::from("vfx_plonk_seeded.params")
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
    } else if let Some(radix) = zcash {
        // Production: circuit keys over the Zcash Powers of Tau universal parameters.
        let include_pk = !verify_only;
        eprintln!("Reading Zcash Powers of Tau phase1radix file {} ...", radix.display());
        let bytes = fs::read(&radix)?;
        eprintln!("Recovering monomial powers, checking the structure, compiling the v2 circuits (owner-bound notes, bound recipient)...");
        let (blob, report) = verifiedx_circuits::trusted_setup_from_zcash(&bytes, include_pk)?;
        let out_bytes = blob.serialize();
        fs::write(&out, &out_bytes)?;
        eprintln!(
            "Wrote {} bytes to {} (VXPLNK06: v2 circuits over Zcash Powers of Tau; domain {}, {} powers kept, {} pairing checks; {} prover keys).",
            out_bytes.len(),
            out.display(),
            report.domain_size,
            report.powers_kept,
            report.pairing_checks,
            if include_pk { "with" } else { "without" }
        );
    } else {
        if !insecure_seeded {
            eprintln!("Refusing to write production params from the seeded setup (its tau is public).");
            eprintln!("Use: vfx_plonk_setup --zcash <phase1radix2m16 or larger> [out]   (production, VXPLNK06)");
            eprintln!("     vfx_plonk_setup --insecure-seeded [out]                    (tests only, VXPLNK04)");
            std::process::exit(2);
        }
        // Test-only: seeded setup, written with the seeded magic the node refuses.
        let include_pk = !verify_only;
        eprintln!("Compiling v2 circuits (Shield, Transfer, Unshield, Fee; owner-bound notes, bound recipient)...");
        eprintln!("  Include prover keys: {}", include_pk);
        eprintln!("  This may take a few minutes...");

        let blob = verifiedx_circuits::trusted_setup_v1(include_pk)?;
        let bytes = blob.serialize_with_magic(verifiedx_circuits::circuit_keys::PARAMS_MAGIC_SEEDED);
        fs::write(&out, &bytes)?;
        eprintln!(
            "Wrote {} bytes to {} (VXPLNK04: v2 circuits over the SEEDED setup - tests only, the node refuses it; {} prover keys).",
            bytes.len(),
            out.display(),
            if include_pk { "with" } else { "without" }
        );
    }

    Ok(())
}