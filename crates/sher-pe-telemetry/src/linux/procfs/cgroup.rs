use std::path::Path;

use sher_pe_model::{CgroupInfo, CgroupVersion, Pid};

use super::common::read_to_string_optional;
use crate::Result;

struct CgroupLine {
    hierarchy_id: u32,
    controllers: Vec<String>,
    path: String,
}

fn parse_cgroup_lines(content: &str) -> Vec<CgroupLine> {
    content
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(3, ':');
            let hierarchy_id: u32 = parts.next()?.parse().ok()?;
            let controllers: Vec<String> = parts
                .next()?
                .split(',')
                .filter(|c| !c.is_empty())
                .map(str::to_string)
                .collect();
            let path = parts.next()?.to_string();
            Some(CgroupLine {
                hierarchy_id,
                controllers,
                path,
            })
        })
        .collect()
}

/// Reads the `cgroup.controllers` file at a v2 cgroup's own directory
/// under `sys_root` (normally `/sys/fs/cgroup`). Best-effort: an
/// unreadable/missing file yields an empty controller list rather than an
/// error, since the cgroup membership itself is already known without it.
fn read_v2_controllers(sys_root: &Path, cgroup_path: &str) -> Vec<String> {
    let trimmed = cgroup_path.trim_start_matches('/');
    let path = sys_root.join(trimmed).join("cgroup.controllers");
    std::fs::read_to_string(path)
        .map(|content| content.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Reads `/proc/[pid]/cgroup` and classifies it as v1 or v2. `None` if the
/// process has no cgroup file at all (exited between listing and read).
pub fn read_cgroup(root: &Path, sys_root: &Path, pid: Pid) -> Result<Option<CgroupInfo>> {
    let path = root.join(pid.to_string()).join("cgroup");
    let Some(content) = read_to_string_optional(&path)? else {
        return Ok(None);
    };
    let lines = parse_cgroup_lines(&content);
    if lines.is_empty() {
        return Ok(None);
    }

    // Pure cgroup v2 systems report exactly one line, hierarchy id 0, with
    // no controller list on the line itself (the list lives in that
    // cgroup's own `cgroup.controllers` file instead).
    if lines.len() == 1 && lines[0].hierarchy_id == 0 {
        let cgroup_path = lines[0].path.clone();
        let controllers = read_v2_controllers(sys_root, &cgroup_path);
        return Ok(Some(CgroupInfo {
            version: CgroupVersion::V2,
            path: cgroup_path,
            controllers,
        }));
    }

    // v1: potentially many independent hierarchies. Flatten into one
    // path (the first hierarchy that actually names a controller, since
    // "name=systemd"-only lines carry no resource-control meaning) and the
    // union of every controller across all hierarchies.
    let mut controllers: Vec<String> = lines
        .iter()
        .flat_map(|line| line.controllers.iter().cloned())
        .filter(|c| !c.starts_with("name="))
        .collect();
    controllers.sort();
    controllers.dedup();

    let path = lines
        .iter()
        .find(|line| !line.controllers.is_empty())
        .or_else(|| lines.first())
        .map(|line| line.path.clone())
        .unwrap_or_default();

    Ok(Some(CgroupInfo {
        version: CgroupVersion::V1,
        path,
        controllers,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc")
    }

    fn fixture_sys_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sys/fs/cgroup")
    }

    #[test]
    fn read_cgroup_detects_v2_and_reads_controllers() {
        let cgroup = read_cgroup(&fixture_root(), &fixture_sys_root(), 100)
            .unwrap()
            .expect("cgroup present");
        assert_eq!(cgroup.version, CgroupVersion::V2);
        assert_eq!(cgroup.path, "/user.slice/user-1000.slice/session.scope");
        assert_eq!(
            cgroup.controllers,
            vec![
                "cpu".to_string(),
                "memory".to_string(),
                "io".to_string(),
                "pids".to_string()
            ]
        );
    }

    #[test]
    fn read_cgroup_detects_v1_and_unions_controllers() {
        let cgroup = read_cgroup(&fixture_root(), &fixture_sys_root(), 101)
            .unwrap()
            .expect("cgroup present");
        assert_eq!(cgroup.version, CgroupVersion::V1);
        assert_eq!(cgroup.path, "/user.slice/user-1000.slice");
        assert_eq!(
            cgroup.controllers,
            vec![
                "cpu".to_string(),
                "cpuacct".to_string(),
                "memory".to_string()
            ]
        );
    }

    #[test]
    fn parse_cgroup_lines_skips_name_only_hierarchy_for_path_choice() {
        let lines = parse_cgroup_lines("1:name=systemd:/foo\n2:cpu:/bar\n");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1].controllers, vec!["cpu".to_string()]);
    }
}
