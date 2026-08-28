//! Pure data types shared by every SHER Process Explorer crate.
//!
//! Nothing in this crate performs I/O. Every public type derives
//! `Serialize`/`Deserialize` so any downstream consumer (the CLI, a future
//! GUI) gets `--json` output for free without bespoke serialization code.

pub mod cgroup;
pub mod container;
pub mod cpu;
pub mod evidence;
pub mod files;
pub mod io;
pub mod log_entry;
pub mod memory;
pub mod namespace;
pub mod network;
pub mod process;
pub mod profiling;
pub mod scheduler;
pub mod security;
pub mod system;
pub mod thread;
pub mod timeline;
pub mod trace_event;
pub mod tree;

pub use cgroup::{CgroupInfo, CgroupVersion};
pub use container::{ContainerInfo, ContainerRuntime};
pub use cpu::CpuStats;
pub use evidence::{Confidence, Evidence, Finding, Severity};
pub use files::{FileKind, OpenFile};
pub use io::DiskIoStats;
pub use log_entry::LogEntry;
pub use memory::MemoryBreakdown;
pub use namespace::NamespaceInfo;
pub use network::{ConnectionState, NetworkConnection, Protocol};
pub use process::{ProcessSnapshot, ProcessState};
pub use profiling::{HotFunction, SyscallStat};
pub use scheduler::SchedulerStats;
pub use security::SecurityContext;
pub use system::{LoadAverage, SystemMemory, SystemOverview};
pub use thread::ThreadSnapshot;
pub use timeline::{TimelineEvent, TimelineEventKind};
pub use trace_event::TraceEvent;
pub use tree::{FamilyRollup, ProcessTree};

/// Linux process/thread identifier. Matches the kernel's `pid_t` (`i32`).
pub type Pid = i32;
