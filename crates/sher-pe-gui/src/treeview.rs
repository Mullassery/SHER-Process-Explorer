//! Pure tree-flattening logic for the process list: turns a
//! `ProcessTree` plus expand/collapse + search-filter state into an
//! ordered list of rows to draw. Kept free of any `egui` dependency so it
//! can be unit-tested directly, the same way `sher-pe-model::tree` is.

use std::collections::HashSet;

use sher_pe_model::{Pid, ProcessTree};

/// One row of the flattened, indent-ready process list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeRow {
    pub pid: Pid,
    pub depth: usize,
    pub has_children: bool,
}

/// Flattens `tree` into display order (roots sorted by pid, children
/// sorted by pid, depth-first).
///
/// `expanded` controls which collapsed subtrees are hidden — but only
/// when `filter` is empty. A non-empty `filter` force-reveals every
/// ancestor chain leading to a match (by process name, case-insensitive,
/// or exact pid), regardless of collapse state, so a search never hides
/// the very result it found.
pub fn flatten_tree(tree: &ProcessTree, expanded: &HashSet<Pid>, filter: &str) -> Vec<TreeRow> {
    let filter_lower = filter.trim().to_lowercase();
    let mut roots: Vec<Pid> = tree.roots();
    roots.sort();

    let mut rows = Vec::new();
    for root in roots {
        flatten_node(tree, root, 0, expanded, &filter_lower, &mut rows);
    }
    rows
}

fn flatten_node(
    tree: &ProcessTree,
    pid: Pid,
    depth: usize,
    expanded: &HashSet<Pid>,
    filter_lower: &str,
    rows: &mut Vec<TreeRow>,
) {
    if !subtree_matches(tree, pid, filter_lower) {
        return;
    }

    let mut children = tree.children.get(&pid).cloned().unwrap_or_default();
    children.sort();
    rows.push(TreeRow {
        pid,
        depth,
        has_children: !children.is_empty(),
    });

    let force_expand_for_search = !filter_lower.is_empty();
    if force_expand_for_search || expanded.contains(&pid) {
        for child in children {
            flatten_node(tree, child, depth + 1, expanded, filter_lower, rows);
        }
    }
}

/// True if `pid` itself matches `filter_lower`, or any descendant does.
/// An empty filter matches everything.
fn subtree_matches(tree: &ProcessTree, pid: Pid, filter_lower: &str) -> bool {
    if filter_lower.is_empty() {
        return true;
    }
    let self_matches = tree
        .nodes
        .get(&pid)
        .map(|node| {
            node.name.to_lowercase().contains(filter_lower) || pid.to_string() == filter_lower
        })
        .unwrap_or(false);
    if self_matches {
        return true;
    }
    tree.children
        .get(&pid)
        .map(|children| {
            children
                .iter()
                .any(|&child| subtree_matches(tree, child, filter_lower))
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sher_pe_model::{CpuStats, MemoryBreakdown, ProcessSnapshot, ProcessState};

    fn snap(pid: Pid, ppid: Pid, name: &str) -> ProcessSnapshot {
        ProcessSnapshot {
            pid,
            ppid,
            name: name.to_string(),
            cmdline: vec![],
            exe: None,
            state: ProcessState::Running,
            uid: 1000,
            gid: 1000,
            start_time: 0,
            cpu: CpuStats::default(),
            memory: MemoryBreakdown::default(),
            thread_count: 1,
            open_file_count: 0,
            cgroup: None,
        }
    }

    /// 1 (init) -> 2 (sshd) -> 3 (bash) -> 4 (vim)
    ///          -> 5 (cron)
    fn sample_tree() -> ProcessTree {
        ProcessTree::build([
            snap(1, 0, "init"),
            snap(2, 1, "sshd"),
            snap(3, 2, "bash"),
            snap(4, 3, "vim"),
            snap(5, 1, "cron"),
        ])
    }

    #[test]
    fn flatten_empty_tree_is_empty() {
        let tree = ProcessTree::default();
        assert_eq!(flatten_tree(&tree, &HashSet::new(), ""), vec![]);
    }

    #[test]
    fn flatten_with_no_expansion_and_no_filter_shows_only_roots() {
        let tree = sample_tree();
        let rows = flatten_tree(&tree, &HashSet::new(), "");
        assert_eq!(
            rows,
            vec![TreeRow {
                pid: 1,
                depth: 0,
                has_children: true
            }]
        );
    }

    #[test]
    fn flatten_reveals_children_of_expanded_nodes_only() {
        let tree = sample_tree();
        let expanded: HashSet<Pid> = HashSet::from([1]);
        let rows = flatten_tree(&tree, &expanded, "");
        // pid 1 expanded reveals 2 and 5, but 2 itself isn't expanded so
        // pid 3 (and further descendants) stay hidden.
        assert_eq!(
            rows,
            vec![
                TreeRow {
                    pid: 1,
                    depth: 0,
                    has_children: true
                },
                TreeRow {
                    pid: 2,
                    depth: 1,
                    has_children: true
                },
                TreeRow {
                    pid: 5,
                    depth: 1,
                    has_children: false
                },
            ]
        );
    }

    #[test]
    fn flatten_expands_full_chain_when_all_ancestors_expanded() {
        let tree = sample_tree();
        let expanded: HashSet<Pid> = HashSet::from([1, 2, 3]);
        let rows = flatten_tree(&tree, &expanded, "");
        let pids: Vec<Pid> = rows.iter().map(|r| r.pid).collect();
        assert_eq!(pids, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn filter_matching_only_a_deep_descendant_reveals_its_whole_ancestor_chain() {
        let tree = sample_tree();
        // Nothing expanded — a collapse-respecting flatten would normally
        // hide pid 4 entirely, but a search for "vim" must still surface
        // the path down to it.
        let rows = flatten_tree(&tree, &HashSet::new(), "vim");
        let pids: Vec<Pid> = rows.iter().map(|r| r.pid).collect();
        assert_eq!(pids, vec![1, 2, 3, 4]);
    }

    #[test]
    fn filter_excludes_siblings_that_do_not_match_and_have_no_matching_descendants() {
        let tree = sample_tree();
        let rows = flatten_tree(&tree, &HashSet::new(), "vim");
        // pid 5 (cron) shares root pid 1 with the match but isn't on the
        // path to it, so it must not appear.
        assert!(!rows.iter().any(|r| r.pid == 5));
    }

    #[test]
    fn filter_matching_nothing_yields_empty_rows() {
        let tree = sample_tree();
        let rows = flatten_tree(&tree, &HashSet::new(), "nonexistent-process-name");
        assert_eq!(rows, vec![]);
    }

    #[test]
    fn filter_by_exact_pid_matches() {
        let tree = sample_tree();
        let rows = flatten_tree(&tree, &HashSet::new(), "5");
        let pids: Vec<Pid> = rows.iter().map(|r| r.pid).collect();
        assert_eq!(pids, vec![1, 5]);
    }

    #[test]
    fn filter_is_case_insensitive() {
        let tree = sample_tree();
        let rows = flatten_tree(&tree, &HashSet::new(), "BASH");
        let pids: Vec<Pid> = rows.iter().map(|r| r.pid).collect();
        assert_eq!(pids, vec![1, 2, 3]);
    }
}
