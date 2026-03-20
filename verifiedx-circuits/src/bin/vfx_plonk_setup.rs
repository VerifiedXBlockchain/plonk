//! Generate `VXPLNK01` params blob for VerifiedX v0 PLONK (writes path from argv or `vfx_plonk_v0.params`).
use std::env;
use std::fs;
use std::path::PathBuf;

use verifiedx_circuits::{trusted_setup_v0, VfxPlonkParamsBlob};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out: PathBuf = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("vfx_plonk_v0.params"));

    let blob: VfxPlonkParamsBlob = trusted_setup_v0()?;
    let bytes = blob.serialize()?;
    fs::write(&out, &bytes)?;
    eprintln!(
        "Wrote {} bytes to {} (VXPLNK01 v0 PI-digest binding — not production privacy yet).",
        bytes.len(),
        out.display()
    );
    Ok(())
}
