use std::collections::HashSet;
use std::time::{Duration, Instant};

use sher_pe_intelligence::ProcessIntelligence;
use sher_pe_investigation as investigation;
use sher_pe_model::{Finding, Pid};

use crate::treeview::flatten_tree;

/// How often the process table is re-read. CPU% is computed by
/// `ProcessIntelligence` from tick deltas across two `refresh()` calls, so
/// this also controls how quickly CPU% becomes meaningful after opening
/// the app (the first tick always shows 0%).
const REFRESH_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DetailTab {
    Overview,
    Memory,
    Cpu,
    Threads,
    Files,
    Network,
    Disk,
    Security,
}

const ALL_TABS: [DetailTab; 8] = [
    DetailTab::Overview,
    DetailTab::Memory,
    DetailTab::Cpu,
    DetailTab::Threads,
    DetailTab::Files,
    DetailTab::Network,
    DetailTab::Disk,
    DetailTab::Security,
];

impl DetailTab {
    fn label(self) -> &'static str {
        match self {
            DetailTab::Overview => "Overview",
            DetailTab::Memory => "Memory",
            DetailTab::Cpu => "CPU",
            DetailTab::Threads => "Threads",
            DetailTab::Files => "Files",
            DetailTab::Network => "Network",
            DetailTab::Disk => "Disk I/O",
            DetailTab::Security => "Security",
        }
    }
}

/// The last "why" `Finding` computed for a given pid+tab combination, kept
/// around after the button is clicked until the user asks again — a stale
/// finding still shows correctly-labeled evidence, it's just not the
/// latest reading.
struct CachedFinding {
    pid: Pid,
    tab: DetailTab,
    finding: Finding,
}

pub struct SherApp {
    intel: ProcessIntelligence,
    last_refresh: Instant,
    /// Set once, on the first failed `refresh()` — most likely "this
    /// isn't Linux" or "`/proc` isn't readable." Shown as a persistent
    /// banner rather than silently leaving the tree empty.
    refresh_error: Option<String>,
    expanded: HashSet<Pid>,
    filter: String,
    selected: Option<Pid>,
    selected_tab: DetailTab,
    cached_finding: Option<CachedFinding>,
}

impl SherApp {
    pub fn new(intel: ProcessIntelligence) -> Self {
        let mut app = Self {
            intel,
            last_refresh: Instant::now(),
            refresh_error: None,
            expanded: HashSet::new(),
            filter: String::new(),
            selected: None,
            selected_tab: DetailTab::Overview,
            cached_finding: None,
        };
        app.refresh();
        app
    }

    fn refresh(&mut self) {
        self.last_refresh = Instant::now();
        if let Err(err) = self.intel.refresh() {
            self.refresh_error = Some(err.to_string());
        } else {
            self.refresh_error = None;
        }
    }

    fn finding_for(&mut self, tab: DetailTab, pid: Pid) -> &Finding {
        let needs_recompute = match &self.cached_finding {
            Some(cached) => cached.pid != pid || cached.tab != tab,
            None => true,
        };
        if needs_recompute {
            let finding = match tab {
                DetailTab::Cpu => investigation::why_cpu(&self.intel, pid),
                DetailTab::Memory => investigation::why_memory(&self.intel, pid),
                DetailTab::Network => investigation::why_network(&self.intel, pid),
                DetailTab::Disk => investigation::why_disk(&self.intel, pid),
                _ => unreachable!("finding_for only called for tabs with a Why? button"),
            };
            self.cached_finding = Some(CachedFinding { pid, tab, finding });
        }
        &self
            .cached_finding
            .as_ref()
            .expect("just set above")
            .finding
    }
}

impl eframe::App for SherApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if self.last_refresh.elapsed() >= REFRESH_INTERVAL {
            self.refresh();
        }
        ui.ctx().request_repaint_after(Duration::from_millis(500));

        egui::Panel::top("top_bar").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading("SHER Process Explorer");
                ui.separator();
                ui.label("Search:");
                ui.text_edit_singleline(&mut self.filter);
                if ui.button("Refresh now").clicked() {
                    self.refresh();
                }
            });
            if let Some(err) = &self.refresh_error {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 80, 80),
                    format!("refresh failed: {err}"),
                );
            }
        });

        egui::Panel::left("process_tree")
            .resizable(true)
            .show(ui, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    self.draw_tree(ui);
                });
            });

        egui::CentralPanel::default().show(ui, |ui| {
            self.draw_detail(ui);
        });
    }
}

impl SherApp {
    fn draw_tree(&mut self, ui: &mut egui::Ui) {
        let tree = self.intel.tree();
        let rows = flatten_tree(&tree, &self.expanded, &self.filter);
        if rows.is_empty() {
            ui.weak("(no processes match)");
            return;
        }
        for row in rows {
            let Some(process) = tree.nodes.get(&row.pid) else {
                continue;
            };
            ui.horizontal(|ui| {
                ui.add_space(row.depth as f32 * 16.0);
                if row.has_children {
                    let mut is_expanded = self.expanded.contains(&row.pid);
                    if ui.checkbox(&mut is_expanded, "").changed() {
                        if is_expanded {
                            self.expanded.insert(row.pid);
                        } else {
                            self.expanded.remove(&row.pid);
                        }
                    }
                } else {
                    ui.add_space(20.0);
                }
                let label = format!(
                    "{} (pid {}, {:.1}% CPU)",
                    process.name, row.pid, process.cpu.percent
                );
                let is_selected = self.selected == Some(row.pid);
                if ui.selectable_label(is_selected, label).clicked() {
                    self.selected = Some(row.pid);
                    self.cached_finding = None;
                }
            });
        }
    }

    fn draw_detail(&mut self, ui: &mut egui::Ui) {
        let Some(pid) = self.selected else {
            ui.weak("Select a process on the left to see detail.");
            return;
        };
        let Some(process) = self.intel.process(pid).cloned() else {
            ui.weak(format!("pid {pid} is no longer running."));
            return;
        };

        ui.horizontal(|ui| {
            for tab in ALL_TABS {
                if ui
                    .selectable_label(self.selected_tab == tab, tab.label())
                    .clicked()
                {
                    self.selected_tab = tab;
                }
            }
        });
        ui.separator();

        match self.selected_tab {
            DetailTab::Overview => self.draw_overview(ui, pid, &process),
            DetailTab::Memory => self.draw_memory(ui, pid, &process),
            DetailTab::Cpu => self.draw_cpu(ui, pid, &process),
            DetailTab::Threads => self.draw_threads(ui, pid),
            DetailTab::Files => self.draw_files(ui, pid),
            DetailTab::Network => self.draw_network(ui, pid),
            DetailTab::Disk => self.draw_disk(ui, pid),
            DetailTab::Security => self.draw_security(ui, pid),
        }
    }

    fn draw_overview(
        &mut self,
        ui: &mut egui::Ui,
        pid: Pid,
        process: &sher_pe_model::ProcessSnapshot,
    ) {
        egui::Grid::new("overview_grid")
            .num_columns(2)
            .show(ui, |ui| {
                ui.label("PID");
                ui.label(pid.to_string());
                ui.end_row();
                ui.label("PPID");
                ui.label(process.ppid.to_string());
                ui.end_row();
                ui.label("Name");
                ui.label(&process.name);
                ui.end_row();
                ui.label("State");
                ui.label(format!("{:?}", process.state));
                ui.end_row();
                ui.label("UID/GID");
                ui.label(format!("{}/{}", process.uid, process.gid));
                ui.end_row();
                ui.label("Command");
                ui.label(process.cmdline.join(" "));
                ui.end_row();
                ui.label("Executable");
                ui.label(process.exe.as_deref().unwrap_or("(unknown)"));
                ui.end_row();
            });
        if let Ok(Some(unit)) = self.intel.systemd_unit(pid) {
            ui.label(format!("systemd unit: {unit}"));
        }
        if let Some(rollup) = self.intel.family_rollup(pid) {
            ui.separator();
            ui.label(format!(
                "Family rollup: {} processes, {:.1}% CPU, {} KB RSS, {} threads, {} open files",
                rollup.process_count,
                rollup.cpu_percent,
                rollup.rss / 1024,
                rollup.thread_count,
                rollup.open_file_count
            ));
        }
    }

    fn draw_memory(
        &mut self,
        ui: &mut egui::Ui,
        pid: Pid,
        process: &sher_pe_model::ProcessSnapshot,
    ) {
        egui::Grid::new("memory_grid")
            .num_columns(2)
            .show(ui, |ui| {
                ui.label("RSS");
                ui.label(format!("{} KB", process.memory.rss / 1024));
                ui.end_row();
                ui.label("VSZ");
                ui.label(format!("{} KB", process.memory.vsz / 1024));
                ui.end_row();
                if process.memory.is_detailed() {
                    ui.label("Anonymous");
                    ui.label(format!("{} KB", process.memory.anonymous / 1024));
                    ui.end_row();
                    ui.label("File-backed");
                    ui.label(format!("{} KB", process.memory.file_backed / 1024));
                    ui.end_row();
                    ui.label("Shared");
                    ui.label(format!("{} KB", process.memory.shared / 1024));
                    ui.end_row();
                    ui.label("Private");
                    ui.label(format!("{} KB", process.memory.private / 1024));
                    ui.end_row();
                }
                ui.label("Swap");
                ui.label(format!("{} KB", process.memory.swap / 1024));
                ui.end_row();
            });
        if !process.memory.is_detailed() {
            ui.weak("(detailed anon/file/shared/private breakdown unavailable on this kernel)");
        }
        ui.separator();
        if ui.button("Why?").clicked() {
            self.cached_finding = None;
            let _ = self.finding_for(DetailTab::Memory, pid);
        }
        draw_finding_if_cached(ui, &self.cached_finding, DetailTab::Memory, pid);
    }

    fn draw_cpu(&mut self, ui: &mut egui::Ui, pid: Pid, process: &sher_pe_model::ProcessSnapshot) {
        egui::Grid::new("cpu_grid").num_columns(2).show(ui, |ui| {
            ui.label("Percent");
            ui.label(format!("{:.1}%", process.cpu.percent));
            ui.end_row();
            ui.label("User ticks");
            ui.label(process.cpu.utime_ticks.to_string());
            ui.end_row();
            ui.label("System ticks");
            ui.label(process.cpu.stime_ticks.to_string());
            ui.end_row();
        });
        ui.separator();
        if ui.button("Why?").clicked() {
            self.cached_finding = None;
            let _ = self.finding_for(DetailTab::Cpu, pid);
        }
        draw_finding_if_cached(ui, &self.cached_finding, DetailTab::Cpu, pid);
    }

    fn draw_threads(&mut self, ui: &mut egui::Ui, pid: Pid) {
        match self.intel.threads(pid) {
            Ok(threads) if threads.is_empty() => {
                ui.weak("(no threads)");
            }
            Ok(threads) => {
                egui::Grid::new("threads_grid")
                    .num_columns(4)
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("TID");
                        ui.strong("Name");
                        ui.strong("State");
                        ui.strong("Priority/Nice");
                        ui.end_row();
                        for thread in threads {
                            ui.label(thread.tid.to_string());
                            ui.label(thread.name);
                            ui.label(format!("{:?}", thread.state));
                            ui.label(format!("{}/{}", thread.priority, thread.nice));
                            ui.end_row();
                        }
                    });
            }
            Err(err) => {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 160, 60),
                    format!("unavailable: {err}"),
                );
            }
        }
    }

    fn draw_files(&mut self, ui: &mut egui::Ui, pid: Pid) {
        match self.intel.open_files(pid) {
            Ok(files) if files.is_empty() => {
                ui.weak("(no open files)");
            }
            Ok(files) => {
                egui::ScrollArea::vertical()
                    .max_height(400.0)
                    .show(ui, |ui| {
                        egui::Grid::new("files_grid")
                            .num_columns(3)
                            .striped(true)
                            .show(ui, |ui| {
                                ui.strong("FD");
                                ui.strong("Kind");
                                ui.strong("Path");
                                ui.end_row();
                                for file in files {
                                    ui.label(file.fd.to_string());
                                    ui.label(format!("{:?}", file.kind));
                                    ui.label(file.path);
                                    ui.end_row();
                                }
                            });
                    });
            }
            Err(err) => {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 160, 60),
                    format!("unavailable: {err}"),
                );
            }
        }
    }

    fn draw_network(&mut self, ui: &mut egui::Ui, pid: Pid) {
        match self.intel.connections(pid) {
            Ok(conns) if conns.is_empty() => {
                ui.weak("(no open connections)");
            }
            Ok(conns) => {
                egui::Grid::new("network_grid")
                    .num_columns(4)
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("Protocol");
                        ui.strong("Local");
                        ui.strong("Remote");
                        ui.strong("State");
                        ui.end_row();
                        for conn in conns {
                            ui.label(format!("{:?}", conn.protocol));
                            ui.label(conn.local_addr);
                            ui.label(conn.remote_addr);
                            ui.label(format!("{:?}", conn.state));
                            ui.end_row();
                        }
                    });
            }
            Err(err) => {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 160, 60),
                    format!("unavailable: {err}"),
                );
            }
        }
        ui.separator();
        if ui.button("Why?").clicked() {
            self.cached_finding = None;
            let _ = self.finding_for(DetailTab::Network, pid);
        }
        draw_finding_if_cached(ui, &self.cached_finding, DetailTab::Network, pid);
    }

    fn draw_disk(&mut self, ui: &mut egui::Ui, pid: Pid) {
        match self.intel.disk_io(pid) {
            Ok(io) => {
                egui::Grid::new("disk_grid").num_columns(2).show(ui, |ui| {
                    ui.label("Read (cumulative)");
                    ui.label(format!("{} bytes", io.read_bytes));
                    ui.end_row();
                    ui.label("Written (cumulative)");
                    ui.label(format!("{} bytes", io.write_bytes));
                    ui.end_row();
                });
            }
            Err(err) => {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 160, 60),
                    format!("unavailable: {err}"),
                );
            }
        }
        ui.separator();
        if ui.button("Why?").clicked() {
            self.cached_finding = None;
            let _ = self.finding_for(DetailTab::Disk, pid);
        }
        draw_finding_if_cached(ui, &self.cached_finding, DetailTab::Disk, pid);
    }

    fn draw_security(&mut self, ui: &mut egui::Ui, pid: Pid) {
        match self.intel.security(pid) {
            Ok(sec) => {
                egui::Grid::new("security_grid")
                    .num_columns(2)
                    .show(ui, |ui| {
                        ui.label("UID/GID (real)");
                        ui.label(format!("{}/{}", sec.uid, sec.gid));
                        ui.end_row();
                        ui.label("UID/GID (effective)");
                        ui.label(format!("{}/{}", sec.euid, sec.egid));
                        ui.end_row();
                        ui.label("Effective capabilities");
                        ui.label(sec.capabilities_effective.join(", "));
                        ui.end_row();
                        ui.label("Seccomp mode");
                        ui.label(sec.seccomp_mode.to_string());
                        ui.end_row();
                        ui.label("LSM label");
                        ui.label(sec.lsm_label.as_deref().unwrap_or("(none)"));
                        ui.end_row();
                    });
            }
            Err(err) => {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 160, 60),
                    format!("unavailable: {err}"),
                );
            }
        }
    }
}

fn draw_finding_if_cached(
    ui: &mut egui::Ui,
    cached: &Option<CachedFinding>,
    tab: DetailTab,
    pid: Pid,
) {
    let Some(cached) = cached else { return };
    if cached.pid != pid || cached.tab != tab {
        return;
    }
    let finding = &cached.finding;
    ui.group(|ui| {
        ui.strong(format!(
            "[{:?}/{:?}] {}",
            finding.severity, finding.confidence, finding.title
        ));
        ui.label(&finding.narrative);
        for evidence in &finding.evidence {
            ui.weak(format!(
                "- {} ({}): {}",
                evidence.description, evidence.source, evidence.raw
            ));
        }
    });
}
