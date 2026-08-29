//! Persistent, long-term process history — the piece `sher-pe-intelligence`
//! deliberately doesn't provide, since its in-memory history/timeline are
//! capacity-bounded (120 ticks, 1000 events) and gone the moment a process
//! is dropped from `ProcessIntelligence` and the CLI/GUI process exits.
//! `sher-pe-daemon` writes here on every tick; `sher-pe-cli`'s `sher
//! history` command reads it back, independent of whether the pid it's
//! asking about is still alive.
//!
//! Backed by real SQLite (via `rusqlite`'s bundled build, so no system
//! `libsqlite3` dependency), not an in-memory stand-in — this is meant to
//! survive the daemon restarting and outlive any single CLI invocation.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use sher_pe_model::{Pid, ProcessSnapshot, TimelineEvent};

pub type Result<T> = std::result::Result<T, HistoryError>;

#[derive(Debug, thiserror::Error)]
pub enum HistoryError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("failed to serialize/deserialize snapshot or event: {0}")]
    Json(#[from] serde_json::Error),
}

/// A SQLite-backed store for process snapshots and timeline events,
/// keyed by `(pid, start_time)` — the same PID-reuse-safe key
/// `sher-pe-intelligence` uses in memory.
pub struct HistoryStore {
    conn: Connection,
}

impl HistoryStore {
    /// Opens (creating if necessary, including parent directories) the
    /// SQLite database at `path` and ensures its schema exists.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CANTOPEN),
                    Some(format!("failed to create {}: {e}", parent.display())),
                )
            })?;
        }
        let conn = Connection::open(path)?;
        Self::migrate(&conn)?;
        Ok(Self { conn })
    }

    /// An in-memory store — used by tests so they never touch the
    /// filesystem.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::migrate(&conn)?;
        Ok(Self { conn })
    }

    fn migrate(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pid INTEGER NOT NULL,
                start_time INTEGER NOT NULL,
                sampled_at INTEGER NOT NULL,
                name TEXT NOT NULL,
                snapshot_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_snapshots_pid_start
                ON snapshots(pid, start_time);
            CREATE INDEX IF NOT EXISTS idx_snapshots_sampled_at
                ON snapshots(sampled_at);

            CREATE TABLE IF NOT EXISTS timeline_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pid INTEGER NOT NULL,
                at INTEGER NOT NULL,
                event_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_pid ON timeline_events(pid);
            CREATE INDEX IF NOT EXISTS idx_events_at ON timeline_events(at);
            ",
        )?;
        Ok(())
    }

    /// Records one process snapshot, taken at `sampled_at` (unix seconds).
    pub fn record_snapshot(&self, snapshot: &ProcessSnapshot, sampled_at: i64) -> Result<()> {
        let json = serde_json::to_string(snapshot)?;
        self.conn.execute(
            "INSERT INTO snapshots (pid, start_time, sampled_at, name, snapshot_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                snapshot.pid,
                snapshot.start_time as i64,
                sampled_at,
                snapshot.name,
                json
            ],
        )?;
        Ok(())
    }

    /// Records one timeline event.
    pub fn record_event(&self, event: &TimelineEvent) -> Result<()> {
        let json = serde_json::to_string(event)?;
        self.conn.execute(
            "INSERT INTO timeline_events (pid, at, event_json) VALUES (?1, ?2, ?3)",
            params![event.pid, event.at, json],
        )?;
        Ok(())
    }

    /// Every persisted snapshot for `pid`, oldest first, sampled at or
    /// after `since` (unix seconds). Spans every `(pid, start_time)`
    /// generation of that bare pid unless `start_time` is used to filter
    /// further by the caller — kept simple since the common query is
    /// "show me everything about pid N recently," not a specific run.
    pub fn snapshots_for(&self, pid: Pid, since: i64) -> Result<Vec<(i64, ProcessSnapshot)>> {
        let mut stmt = self.conn.prepare(
            "SELECT sampled_at, snapshot_json FROM snapshots
             WHERE pid = ?1 AND sampled_at >= ?2
             ORDER BY sampled_at ASC",
        )?;
        let rows = stmt.query_map(params![pid, since], |row| {
            let sampled_at: i64 = row.get(0)?;
            let json: String = row.get(1)?;
            Ok((sampled_at, json))
        })?;
        let mut result = Vec::new();
        for row in rows {
            let (sampled_at, json) = row?;
            let snapshot: ProcessSnapshot = serde_json::from_str(&json)?;
            result.push((sampled_at, snapshot));
        }
        Ok(result)
    }

    /// Every persisted timeline event for `pid`, oldest first, at or
    /// after `since` (unix seconds).
    pub fn events_for(&self, pid: Pid, since: i64) -> Result<Vec<TimelineEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT event_json FROM timeline_events
             WHERE pid = ?1 AND at >= ?2
             ORDER BY at ASC",
        )?;
        let rows = stmt.query_map(params![pid, since], |row| row.get::<_, String>(0))?;
        let mut result = Vec::new();
        for row in rows {
            result.push(serde_json::from_str(&row?)?);
        }
        Ok(result)
    }

    /// Deletes every snapshot/event older than `cutoff` (unix seconds),
    /// keeping the database from growing without bound. Returns the
    /// total number of rows removed.
    pub fn prune_older_than(&self, cutoff: i64) -> Result<usize> {
        let snapshots_removed = self.conn.execute(
            "DELETE FROM snapshots WHERE sampled_at < ?1",
            params![cutoff],
        )?;
        let events_removed = self
            .conn
            .execute("DELETE FROM timeline_events WHERE at < ?1", params![cutoff])?;
        Ok(snapshots_removed + events_removed)
    }

    /// Total number of snapshot rows currently stored — used by tests and
    /// `sherd`'s own startup log line, not exposed as a general query API.
    pub fn snapshot_count(&self) -> Result<u64> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM snapshots", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    /// The most recent `sampled_at` recorded for any pid, if any snapshot
    /// has ever been written. Used by `sherd` to report how far back its
    /// own history already reaches on startup.
    pub fn oldest_sampled_at(&self) -> Result<Option<i64>> {
        self.conn
            .query_row("SELECT MIN(sampled_at) FROM snapshots", [], |row| {
                row.get(0)
            })
            .optional()
            .map(|v| v.flatten())
            .map_err(HistoryError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sher_pe_model::{CpuStats, MemoryBreakdown, ProcessState, TimelineEventKind};

    fn snap(pid: Pid, start_time: u64, rss: u64) -> ProcessSnapshot {
        ProcessSnapshot {
            pid,
            ppid: 1,
            pgid: pid,
            sid: pid,
            name: format!("proc-{pid}"),
            cmdline: vec![],
            exe: None,
            state: ProcessState::Running,
            uid: 1000,
            gid: 1000,
            start_time,
            cpu: CpuStats::default(),
            memory: MemoryBreakdown {
                rss,
                ..Default::default()
            },
            thread_count: 1,
            open_file_count: 0,
            cgroup: None,
        }
    }

    #[test]
    fn record_and_query_snapshots_round_trip() {
        let store = HistoryStore::open_in_memory().unwrap();
        store.record_snapshot(&snap(1, 100, 1000), 1000).unwrap();
        store.record_snapshot(&snap(1, 100, 2000), 1010).unwrap();

        let history = store.snapshots_for(1, 0).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].1.memory.rss, 1000);
        assert_eq!(history[1].1.memory.rss, 2000);
    }

    #[test]
    fn snapshots_for_respects_since_filter() {
        let store = HistoryStore::open_in_memory().unwrap();
        store.record_snapshot(&snap(1, 100, 1000), 1000).unwrap();
        store.record_snapshot(&snap(1, 100, 2000), 2000).unwrap();

        let history = store.snapshots_for(1, 1500).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].0, 2000);
    }

    #[test]
    fn record_and_query_events_round_trip() {
        let store = HistoryStore::open_in_memory().unwrap();
        let event = TimelineEvent {
            pid: 7,
            at: 500,
            kind: TimelineEventKind::Exited {
                exit_reason: Some("OOM".into()),
            },
            description: "proc-7 exited".into(),
        };
        store.record_event(&event).unwrap();

        let events = store.events_for(7, 0).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], event);
    }

    #[test]
    fn prune_older_than_removes_only_old_rows() {
        let store = HistoryStore::open_in_memory().unwrap();
        store.record_snapshot(&snap(1, 100, 1000), 100).unwrap();
        store.record_snapshot(&snap(1, 100, 2000), 9000).unwrap();
        store
            .record_event(&TimelineEvent {
                pid: 1,
                at: 100,
                kind: TimelineEventKind::Started,
                description: "started".into(),
            })
            .unwrap();

        let removed = store.prune_older_than(5000).unwrap();
        assert_eq!(removed, 2); // one snapshot + one event, both at t=100

        let remaining = store.snapshots_for(1, 0).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].0, 9000);
    }

    #[test]
    fn survives_pid_reuse_as_distinct_start_times_in_the_same_query() {
        // snapshots_for queries by bare pid (see its doc comment) - a
        // caller that cares about a specific run must filter by
        // start_time itself from the returned ProcessSnapshot::start_time.
        let store = HistoryStore::open_in_memory().unwrap();
        store.record_snapshot(&snap(1, 100, 1000), 100).unwrap();
        store.record_snapshot(&snap(1, 999, 5000), 200).unwrap();

        let history = store.snapshots_for(1, 0).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].1.start_time, 100);
        assert_eq!(history[1].1.start_time, 999);
    }

    #[test]
    fn snapshot_count_and_oldest_sampled_at() {
        let store = HistoryStore::open_in_memory().unwrap();
        assert_eq!(store.snapshot_count().unwrap(), 0);
        assert_eq!(store.oldest_sampled_at().unwrap(), None);

        store.record_snapshot(&snap(1, 100, 1000), 500).unwrap();
        store.record_snapshot(&snap(2, 200, 2000), 800).unwrap();

        assert_eq!(store.snapshot_count().unwrap(), 2);
        assert_eq!(store.oldest_sampled_at().unwrap(), Some(500));
    }
}
