//! `sher-gui` — the Phase 1 desktop UI for SHER Process Explorer. Calls
//! the exact same `sher-pe-intelligence`/`sher-pe-investigation` APIs the
//! `sher` CLI uses; no separate logic lives here, only presentation.

mod app;
mod treeview;

use app::SherApp;
use sher_pe_intelligence::ProcessIntelligence;
use sher_pe_telemetry::linux::LinuxAdapter;

fn main() -> eframe::Result {
    // Unlike the CLI (which is one-shot and refuses to run at all off
    // Linux), the GUI still opens on any OS — there's real value in being
    // able to view/tweak the UI itself without a Linux machine on hand.
    // `SherApp` surfaces the "no real /proc" failure as an in-window
    // banner instead of empty-but-silent data.
    if !cfg!(target_os = "linux") {
        eprintln!(
            "sher-gui: not running on Linux (built for {}) — the process tree will be empty; \
             see the in-window banner.",
            std::env::consts::OS
        );
    }

    let adapter = LinuxAdapter::new();
    let intel = ProcessIntelligence::new(Box::new(adapter));

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1100.0, 700.0]),
        ..Default::default()
    };
    eframe::run_native(
        "SHER Process Explorer",
        options,
        Box::new(|_cc| Ok(Box::new(SherApp::new(intel)))),
    )
}
