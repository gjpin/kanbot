//! Each workspace that fails waits on its own before it is tried again,
//! longer each time it fails again: one that keeps failing neither makes
//! every workspace sync again nor is called every few seconds.

use std::{collections::HashMap, time::Duration};

use tokio::time::Instant;

use super::Scope;
use crate::openshell::model::WorkspaceName;

/// The workspaces that failed, and when each may be tried again.
pub(super) struct Backoff {
    /// The wait after a first failure; it doubles with each failure after.
    first: Duration,
    /// The longest wait.
    max: Duration,
    failing: HashMap<WorkspaceName, Failing>,
}

#[derive(Clone, Copy, Debug)]
struct Failing {
    /// Failures in a row.
    failures: u32,
    retry_at: Instant,
}

impl Backoff {
    pub(super) fn new(first: Duration, max: Duration) -> Self {
        Self {
            first,
            max,
            failing: HashMap::new(),
        }
    }

    /// Whether a run of `scope` at `now` syncs `workspace`: a failed one
    /// only once its wait is over, any other only in a full run.
    pub(super) fn selects(&self, scope: Scope, workspace: &WorkspaceName, now: Instant) -> bool {
        match self.failing.get(workspace) {
            Some(failing) => failing.retry_at <= now,
            None => scope == Scope::All,
        }
    }

    /// `workspace` failed at `now`.
    pub(super) fn failed(&mut self, workspace: &WorkspaceName, now: Instant) {
        let failures = self
            .failing
            .get(workspace)
            .map_or(1, |failing| failing.failures.saturating_add(1));
        let factor = 1_u32
            .checked_shl(failures.saturating_sub(1))
            .unwrap_or(u32::MAX);
        let wait = self.first.saturating_mul(factor).min(self.max);
        let retry_at = now.checked_add(wait).unwrap_or(now);
        self.failing
            .insert(workspace.clone(), Failing { failures, retry_at });
    }

    /// `workspace` synced: no more waiting.
    pub(super) fn succeeded(&mut self, workspace: &WorkspaceName) {
        self.failing.remove(workspace);
    }

    /// Forgets the workspaces `present` does not keep.
    pub(super) fn retain(&mut self, present: impl Fn(&WorkspaceName) -> bool) {
        self.failing.retain(|workspace, _| present(workspace));
    }

    /// Forgets every failure.
    pub(super) fn clear(&mut self) {
        self.failing.clear();
    }

    /// When the next failed workspace may be tried again.
    pub(super) fn next_retry(&self) -> Option<Instant> {
        self.failing.values().map(|failing| failing.retry_at).min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIRST: Duration = Duration::from_secs(30);
    const MAX: Duration = Duration::from_secs(300);

    fn workspace(name: &str) -> WorkspaceName {
        WorkspaceName::parse(name).unwrap()
    }

    #[test]
    fn a_failed_workspace_waits_longer_each_time_up_to_the_maximum() {
        let mut backoff = Backoff::new(FIRST, MAX);
        let alpha = workspace("alpha");
        let start = Instant::now();
        assert_eq!(backoff.next_retry(), None);
        for (failure, wait) in [30, 60, 120, 240, 300, 300].into_iter().enumerate() {
            let now = start + Duration::from_secs(u64::try_from(failure).unwrap());
            backoff.failed(&alpha, now);
            let retry_at = now + Duration::from_secs(wait);
            assert_eq!(backoff.next_retry(), Some(retry_at), "failure {failure}");
            assert!(!backoff.selects(Scope::All, &alpha, retry_at - Duration::from_millis(1)));
            assert!(!backoff.selects(Scope::Failed, &alpha, retry_at - Duration::from_millis(1)));
            assert!(backoff.selects(Scope::All, &alpha, retry_at));
            assert!(backoff.selects(Scope::Failed, &alpha, retry_at));
        }
        // Even after very many failures.
        for _ in 0..100 {
            backoff.failed(&alpha, start);
        }
        assert_eq!(backoff.next_retry(), Some(start + MAX));

        backoff.succeeded(&alpha);
        assert_eq!(backoff.next_retry(), None);
        backoff.failed(&alpha, start);
        assert_eq!(backoff.next_retry(), Some(start + FIRST), "counted afresh");
    }

    #[test]
    fn only_full_runs_sync_workspaces_that_did_not_fail() {
        let mut backoff = Backoff::new(FIRST, MAX);
        let now = Instant::now();
        let (alpha, beta) = (workspace("alpha"), workspace("beta"));
        backoff.failed(&alpha, now);
        assert!(backoff.selects(Scope::All, &beta, now));
        assert!(!backoff.selects(Scope::Failed, &beta, now + MAX));
        assert!(backoff.selects(Scope::Failed, &alpha, now + MAX));
    }

    #[test]
    fn the_earliest_retry_comes_first_and_forgotten_ones_never() {
        let mut backoff = Backoff::new(FIRST, MAX);
        let now = Instant::now();
        let (alpha, beta) = (workspace("alpha"), workspace("beta"));
        backoff.failed(&alpha, now);
        backoff.failed(&alpha, now);
        backoff.failed(&beta, now);
        assert_eq!(backoff.next_retry(), Some(now + FIRST));
        backoff.retain(|workspace| *workspace == alpha);
        assert_eq!(backoff.next_retry(), Some(now + FIRST * 2));
        assert!(
            backoff.selects(Scope::All, &beta, now),
            "beta starts afresh"
        );
        backoff.clear();
        assert_eq!(backoff.next_retry(), None);
        assert!(!backoff.selects(Scope::Failed, &alpha, now + MAX));
    }
}
