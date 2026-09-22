//! Regression test for the stale-copyright-holder bug `ROADMAP_HONEST.md`
//! flagged: `crates/sher-pe-cli/Cargo.toml`'s `[package.metadata.deb]`
//! `copyright` field said `"2026, SHER"` — the pre-Apache-2.0 project-name
//! placeholder — while `LICENSE`'s actual copyright line names a person,
//! `"Georgi Mullassery"`. Not a legal problem, just a config/docs
//! inconsistency that a `.deb` build would have carried forward silently.
//!
//! This is a plain string check rather than a TOML parse to avoid adding a
//! new dependency just for one test; it's intentionally tolerant of
//! whitespace but strict about the copyright holder actually appearing in
//! both files identically.

use std::fs;
use std::path::Path;

#[test]
fn deb_copyright_holder_matches_license_copyright_holder() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let cargo_toml = fs::read_to_string(manifest_dir.join("Cargo.toml"))
        .expect("crates/sher-pe-cli/Cargo.toml must be readable");
    let license = fs::read_to_string(manifest_dir.join("../../LICENSE"))
        .expect("repo-root LICENSE must be readable");

    let license_copyright_line = license
        .lines()
        .find(|line| line.trim_start().starts_with("Copyright "))
        .expect("LICENSE must contain a 'Copyright <year> <holder>' line");
    // e.g. "   Copyright 2026 Georgi Mullassery" -> "Georgi Mullassery"
    let license_holder = license_copyright_line
        .trim()
        .strip_prefix("Copyright ")
        .and_then(|rest| rest.split_once(' ')) // split off the year
        .map(|(_year, holder)| holder.trim())
        .expect("LICENSE copyright line must be 'Copyright <year> <holder>'");

    let deb_copyright_line = cargo_toml
        .lines()
        .find(|line| line.trim_start().starts_with("copyright ="))
        .expect("[package.metadata.deb] must set a 'copyright' field");
    // e.g. `copyright = "2026, Georgi Mullassery"` -> "Georgi Mullassery"
    let deb_holder = deb_copyright_line
        .split('"')
        .nth(1)
        .and_then(|value| value.split_once(", "))
        .map(|(_year, holder)| holder.trim())
        .expect("deb copyright field must be formatted as \"<year>, <holder>\"");

    assert_eq!(
        deb_holder, license_holder,
        "Cargo.toml's [package.metadata.deb] copyright holder ({deb_holder:?}) must match \
         LICENSE's copyright holder ({license_holder:?}) — see ROADMAP_HONEST.md's \
         now-fixed 'SHER' vs. 'Georgi Mullassery' inconsistency"
    );
}
