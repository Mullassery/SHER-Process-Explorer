use std::collections::HashSet;
use std::time::{Duration, Instant};

use sher_pe_intelligence::ProcessIntelligence;
use sher_pe_investigation as investigation;
use sher_pe_model::{Finding, HotFunction, Pid, Signal, SyscallStat};

use crate::treeview::flatten_tree;

/// How often the process table is re-read. CPU% is computed by
/// `ProcessIntelligence` from tick deltas across two `refresh()` calls, so
/// this also controls how quickly CPU% becomes meaningful after opening
/// the app (the first tick always shows 0%).
const REFRESH_INTERVAL: Duration = Duration::from_secs(2);

/// How long a `perf`/`strace` sample runs when the user clicks "Profile"
/// or "Trace syscalls." Both calls block the UI thread for roughly this
/// long — there's no background-thread sampling yet (a real future
/// refinement, not faked here), so the button labels say so up front
/// rather than the window silently freezing with no explanation.
const SAMPLE_DURATION: Duration = Duration::from_secs(3);

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
    Timeline,
}

const ALL_TABS: [DetailTab; 9] = [
    DetailTab::Overview,
    DetailTab::Memory,
    DetailTab::Cpu,
    DetailTab::Threads,
    DetailTab::Files,
    DetailTab::Network,
    DetailTab::Disk,
    DetailTab::Security,
    DetailTab::Timeline,
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
            DetailTab::Timeline => "Timeline",
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
    /// Re-fetched alongside the process table on every `refresh()` tick —
    /// cheap (a handful of `/proc` reads), so no need to defer it to a
    /// button click the way `sample_hot_functions`/`sample_syscalls` are.
    system_overview: Option<sher_pe_model::SystemOverview>,
    expanded: HashSet<Pid>,
    filter: String,
    selected: Option<Pid>,
    selected_tab: DetailTab,
    cached_finding: Option<CachedFinding>,
    cached_hot_functions: Option<(Pid, Result<Vec<HotFunction>, String>)>,
    cached_syscalls: Option<(Pid, Result<Vec<SyscallStat>, String>)>,
    /// A "Terminate"/"Kill" click awaiting explicit confirmation — signals
    /// are real and irreversible, so nothing is sent until the user
    /// confirms this inline prompt.
    pending_signal: Option<(Pid, Signal)>,
    /// The outcome of the most recently *sent* signal, shown until the
    /// next signal is sent or a different process is selected.
    last_signal_result: Option<(Pid, Signal, Result<(), String>)>,
}

impl SherApp {
    pub fn new(intel: ProcessIntelligence) -> Self {
        let mut app = Self {
            intel,
            last_refresh: Instant::now(),
            refresh_error: None,
            system_overview: None,
            expanded: HashSet::new(),
            filter: String::new(),
            selected: None,
            selected_tab: DetailTab::Overview,
            cached_finding: None,
            cached_hot_functions: None,
            cached_syscalls: None,
            pending_signal: None,
            last_signal_result: None,
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
        self.system_overview = self.intel.system_overview().ok();
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
            if let Some(overview) = &self.system_overview {
                let mem = &overview.memory;
                let percent_used = if mem.total > 0 {
                    mem.used() as f64 / mem.total as f64 * 100.0
                } else {
                    0.0
                };
                let uptime_secs = overview.uptime_secs as u64;
                ui.label(format!(
                    "load {:.2} {:.2} {:.2}  |  mem {}/{} MB ({:.0}%)  |  {} processes  |  up {}d {}h {}m",
                    overview.load_average.one_min,
                    overview.load_average.five_min,
                    overview.load_average.fifteen_min,
                    mem.used() / 1024 / 1024,
                    mem.total / 1024 / 1024,
                    percent_used,
                    overview.process_count,
                    uptime_secs / 86400,
                    (uptime_secs % 86400) / 3600,
                    (uptime_secs % 3600) / 60
                ));
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
                    self.cached_hot_functions = None;
                    self.cached_syscalls = None;
                    self.pending_signal = None;
                    self.last_signal_result = None;
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
            DetailTab::Timeline => self.draw_timeline(ui, pid),
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
        if let Ok(Some(container)) = self.intel.container_info(pid) {
            ui.separator();
            ui.label(format!(
                "Container: {:?} {} (image: {}, status: {})",
                container.runtime,
                container.name.as_deref().unwrap_or(&container.id[..12]),
                container.image.as_deref().unwrap_or("unknown"),
                container.status.as_deref().unwrap_or("unknown")
            ));
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

        ui.separator();
        self.draw_process_control(ui, pid);
    }

    /// Terminate/Kill buttons plus an inline confirmation step — signals
    /// are real and irreversible (`Signal::Kill` especially), so nothing
    /// is sent to `intel.send_signal` until the user confirms.
    fn draw_process_control(&mut self, ui: &mut egui::Ui, pid: Pid) {
        ui.horizontal(|ui| {
            if ui.button("Terminate (SIGTERM)").clicked() {
                self.pending_signal = Some((pid, Signal::Term));
            }
            if ui
                .button(
                    egui::RichText::new("Kill (SIGKILL)")
                        .color(egui::Color32::from_rgb(220, 80, 80)),
                )
                .clicked()
            {
                self.pending_signal = Some((pid, Signal::Kill));
            }
        });

        if let Some((confirm_pid, signal)) = self.pending_signal {
            if confirm_pid == pid {
                ui.group(|ui| {
                    ui.colored_label(
                        egui::Color32::from_rgb(220, 160, 60),
                        format!(
                            "Send {signal} to pid {pid}?{}",
                            if signal.is_uncatchable() {
                                " This cannot be caught or ignored by the process."
                            } else {
                                ""
                            }
                        ),
                    );
                    ui.horizontal(|ui| {
                        if ui.button("Confirm").clicked() {
                            let result = self
                                .intel
                                .send_signal(pid, signal)
                                .map_err(|e| e.to_string());
                            self.last_signal_result = Some((pid, signal, result));
                            self.pending_signal = None;
                        }
                        if ui.button("Cancel").clicked() {
                            self.pending_signal = None;
                        }
                    });
                });
            }
        }

        if let Some((result_pid, signal, result)) = &self.last_signal_result {
            if *result_pid == pid {
                match result {
                    Ok(()) => {
                        ui.colored_label(
                            egui::Color32::from_rgb(100, 180, 100),
                            format!("Sent {signal} to pid {pid}."),
                        );
                    }
                    Err(err) => {
                        ui.colored_label(
                            egui::Color32::from_rgb(220, 80, 80),
                            format!("Failed to send {signal} to pid {pid}: {err}"),
                        );
                    }
                }
            }
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
            if let Ok(sched) = self.intel.scheduler_stats(pid) {
                ui.label("On CPU / waiting");
                let wait_label = match sched.wait_ratio_percent() {
                    Some(ratio) => format!(
                        "{}ns / {}ns ({ratio:.1}% waiting)",
                        sched.on_cpu_ns, sched.wait_ns
                    ),
                    None => format!("{}ns / {}ns", sched.on_cpu_ns, sched.wait_ns),
                };
                ui.label(wait_label);
                ui.end_row();
            }
        });
        ui.separator();
        if ui.button("Why?").clicked() {
            self.cached_finding = None;
            let _ = self.finding_for(DetailTab::Cpu, pid);
        }
        draw_finding_if_cached(ui, &self.cached_finding, DetailTab::Cpu, pid);

        ui.separator();
        ui.weak(format!(
            "Sampling below blocks this window for ~{}s while it runs (perf/strace are shelled out to, not backgrounded yet).",
            SAMPLE_DURATION.as_secs()
        ));
        ui.horizontal(|ui| {
            if ui
                .button(format!("Profile ({}s, perf)", SAMPLE_DURATION.as_secs()))
                .clicked()
            {
                let result = self
                    .intel
                    .sample_hot_functions(pid, SAMPLE_DURATION)
                    .map_err(|e| e.to_string());
                self.cached_hot_functions = Some((pid, result));
            }
            if ui
                .button(format!(
                    "Trace syscalls ({}s, strace)",
                    SAMPLE_DURATION.as_secs()
                ))
                .clicked()
            {
                let result = self
                    .intel
                    .sample_syscalls(pid, SAMPLE_DURATION)
                    .map_err(|e| e.to_string());
                self.cached_syscalls = Some((pid, result));
            }
        });

        if let Some((cached_pid, result)) = &self.cached_hot_functions {
            if *cached_pid == pid {
                ui.label("Hot functions:");
                match result {
                    Ok(hot) if hot.is_empty() => {
                        ui.weak("(no samples landed anywhere — process may be idle)");
                    }
                    Ok(hot) => {
                        egui::Grid::new("hotfn_grid")
                            .num_columns(3)
                            .striped(true)
                            .show(ui, |ui| {
                                ui.strong("Overhead");
                                ui.strong("Module");
                                ui.strong("Symbol");
                                ui.end_row();
                                for h in hot {
                                    ui.label(format!("{:.2}%", h.overhead_percent));
                                    ui.label(&h.module);
                                    ui.label(&h.symbol);
                                    ui.end_row();
                                }
                            });
                    }
                    Err(err) => {
                        ui.colored_label(
                            egui::Color32::from_rgb(220, 160, 60),
                            format!("profile failed: {err}"),
                        );
                    }
                }
            }
        }

        if let Some((cached_pid, result)) = &self.cached_syscalls {
            if *cached_pid == pid {
                ui.label("Syscall breakdown:");
                match result {
                    Ok(stats) if stats.is_empty() => {
                        ui.weak("(no syscalls observed — process may be idle)");
                    }
                    Ok(stats) => {
                        egui::Grid::new("syscall_grid")
                            .num_columns(4)
                            .striped(true)
                            .show(ui, |ui| {
                                ui.strong("Calls");
                                ui.strong("Errors");
                                ui.strong("Time%");
                                ui.strong("Syscall");
                                ui.end_row();
                                for s in stats {
                                    ui.label(s.calls.to_string());
                                    ui.label(s.errors.to_string());
                                    ui.label(format!("{:.2}%", s.time_percent));
                                    ui.label(&s.name);
                                    ui.end_row();
                                }
                            });
                    }
                    Err(err) => {
                        ui.colored_label(
                            egui::Color32::from_rgb(220, 160, 60),
                            format!("trace failed: {err}"),
                        );
                    }
                }
            }
        }
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

    /// Recorded lifecycle events merged chronologically with real
    /// journald entries for the process's systemd unit, plus a
    /// separately-labeled best-effort kernel-log correlation (kept
    /// separate rather than merged in — `dmesg`'s timestamps aren't
    /// reliably comparable to journald's real epoch time).
    fn draw_timeline(&mut self, ui: &mut egui::Ui, pid: Pid) {
        let events = self.intel.timeline(pid);
        let journal = self.intel.journal_entries(pid, 200).unwrap_or_default();
        let kernel_log = self.intel.kernel_log_for(pid).unwrap_or_default();

        enum Item<'a> {
            Event(&'a sher_pe_model::TimelineEvent),
            Log(&'a sher_pe_model::LogEntry),
        }
        let mut items: Vec<(i64, Item)> = Vec::with_capacity(events.len() + journal.len());
        items.extend(events.iter().map(|e| (e.at * 1_000_000, Item::Event(e))));
        items.extend(journal.iter().map(|l| (l.at_us, Item::Log(l))));
        items.sort_by_key(|(at_us, _)| *at_us);

        if items.is_empty() {
            ui.weak("(no recorded lifecycle events or journal entries yet)");
        } else {
            egui::ScrollArea::vertical()
                .max_height(400.0)
                .id_salt("timeline_scroll")
                .show(ui, |ui| {
                    egui::Grid::new("timeline_grid")
                        .num_columns(3)
                        .striped(true)
                        .show(ui, |ui| {
                            ui.strong("Time");
                            ui.strong("Kind");
                            ui.strong("Description");
                            ui.end_row();
                            for (at_us, item) in &items {
                                let secs = at_us / 1_000_000;
                                match item {
                                    Item::Event(e) => {
                                        ui.label(secs.to_string());
                                        ui.label("event");
                                        ui.label(&e.description);
                                    }
                                    Item::Log(l) => {
                                        ui.label(secs.to_string());
                                        ui.label("log");
                                        ui.label(&l.message);
                                    }
                                }
                                ui.end_row();
                            }
                        });
                });
        }

        if !kernel_log.is_empty() {
            ui.separator();
            ui.label("Kernel log (best-effort correlation, not merged into the timeline above):");
            egui::ScrollArea::vertical()
                .max_height(200.0)
                .id_salt("kernel_log_scroll")
                .show(ui, |ui| {
                    for line in &kernel_log {
                        ui.label(line);
                    }
                });
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
