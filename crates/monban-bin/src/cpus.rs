//! Usable CPU count for the P2 `isolation: "auto"` resolution (PLAN-5 D23 option b; F8 `p2.isolation`).
//!
//! The count is the size of this process's CPU affinity set, the set `sched_getaffinity(2)` returns, read without
//! unsafe code from the kernel's own rendering of it: `Cpus_allowed_list` in `/proc/self/status` (for example
//! `0-3,8,10-11`). A process started under `taskset -c 0-3`, or inside a cpuset cgroup that allows 4 CPUs, counts
//! 4. A CFS bandwidth quota (`cpu.max`) does not shrink the set and is not counted. If the file cannot be read or
//! parsed, the fallback is `std::thread::available_parallelism` (itself affinity-based on Linux), and then 1, so an
//! unknown host is treated as small (cordon, the path measured green on the 4-core runner).

/// Usable CPUs of this process (see the module docs). Always ≥ 1.
pub fn usable() -> usize {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| status_cpus(&s))
        .or_else(|| std::thread::available_parallelism().ok().map(usize::from))
        .unwrap_or(1)
        .max(1)
}

/// The `Cpus_allowed_list` count of a `/proc/<pid>/status` text.
fn status_cpus(status: &str) -> Option<usize> {
    status.lines().find_map(|l| l.strip_prefix("Cpus_allowed_list:")).and_then(|v| count_list(v.trim()))
}

/// Number of CPUs in a kernel cpu-list (`0-3,8,10-11`). `None` on any malformed part or an empty set.
fn count_list(list: &str) -> Option<usize> {
    let mut n: usize = 0;
    for part in list.split(',') {
        let part = part.trim();
        let (lo, hi) = match part.split_once('-') {
            Some((a, b)) => (a.parse::<usize>().ok()?, b.parse::<usize>().ok()?),
            None => {
                let v = part.parse::<usize>().ok()?;
                (v, v)
            }
        };
        if hi < lo {
            return None;
        }
        n = n.checked_add(hi - lo)?.checked_add(1)?;
    }
    (n > 0).then_some(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_lists() {
        assert_eq!(count_list("0"), Some(1));
        assert_eq!(count_list("0-3"), Some(4));
        assert_eq!(count_list("0-3,8,10-11"), Some(7));
        assert_eq!(count_list("0-31"), Some(32));
        assert_eq!(count_list(""), None);
        assert_eq!(count_list("3-1"), None);
        assert_eq!(count_list("a"), None);
        assert_eq!(count_list("0-"), None);
    }

    #[test]
    fn status_text() {
        let s = "Name:\tmonban\nCpus_allowed:\tf\nCpus_allowed_list:\t0-3\nMems_allowed_list:\t0\n";
        assert_eq!(status_cpus(s), Some(4));
        assert_eq!(status_cpus("Name:\tx\n"), None);
        assert!(usable() >= 1);
    }
}
