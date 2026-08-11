//! Fixed release schedule for the private surface's protected routes.
//!
//! Every other uniformity this surface enforces is about *bytes*: one envelope
//! width, one refusal, one frame shape. None of that constrains *when* the
//! bytes go out. Without a schedule a protected response is written the moment
//! computation and queueing happen to finish, so a network observer -- in
//! scope under ADR 0010 even though the operator is not -- reads the cost of
//! the round off the wire and learns something about the query that produced
//! it.
//!
//! The schedule closes that channel by writing every protected response at a
//! deadline measured from a fixed reference point: the instant the round was
//! admitted. The bucket width is the compiled profile's existing
//! `timeout_bucket_millis` (ADR 0007 names it as the mechanism) rather than a
//! constant invented here, so the release schedule cannot drift from the
//! budget bound into the profile identifier.
//!
//! Work that does not fit the bucket **fails closed**: the round is cancelled
//! and answered with the uniform refusal, still at the deadline. The
//! alternative -- releasing late -- would leak precisely the queries that were
//! expensive, which is the leak the schedule exists to close, so it is not
//! offered. An overrun means the deployment is provisioned below its own
//! compiled budget, which is an operator's problem to see and fix; it is
//! counted and reported with no query-derived value.

use std::{
    fmt,
    future::Future,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

// `tokio::time::Instant` rather than `std::time::Instant` throughout: it is
// the runtime's mockable clock, so a test can drive a whole bucket under
// `#[tokio::test(start_paused = true)]` without a wall-clock wait. A fixed
// `sleep` used as a synchronisation barrier would be both flaky and
// self-defeating in a change whose entire subject is timing.
use tokio::time::{sleep_until, timeout_at, Instant};

/// The compiled release bucket, plus the operator-visible overrun count.
///
/// Shared by every protected route on one surface: the query route measures
/// its window from admission to the single-admission handler, and the
/// unroutable-request arm measures its own from dispatch, so route probing
/// cannot be told from a refused query by how long the answer took.
pub(crate) struct ReleaseSchedule {
    bucket: Duration,
    overruns: AtomicU64,
}

impl ReleaseSchedule {
    /// Builds a schedule from a compiled profile's `timeout_bucket_millis`.
    pub(crate) const fn from_timeout_bucket_millis(millis: u64) -> Self {
        Self {
            bucket: Duration::from_millis(millis),
            overruns: AtomicU64::new(0),
        }
    }

    /// Opens one round's release window, starting now.
    ///
    /// The caller's own call site is the fixed reference point. It must be a
    /// point reached identically by every protected outcome on that route --
    /// for the query route, the first statement after admission -- or the
    /// schedule would hide only part of the round.
    pub(super) fn admit(&self) -> ReleaseWindow<'_> {
        ReleaseWindow {
            schedule: self,
            deadline: Instant::now() + self.bucket,
        }
    }

    /// Rounds cancelled for exceeding the bucket since this surface started.
    ///
    /// A count, not a rate or a duration: it says the deployment is under its
    /// compiled budget and nothing about which query was running.
    pub(crate) fn overruns(&self) -> u64 {
        self.overruns.load(Ordering::Relaxed)
    }

    /// Records one overrun and reports it exactly once, to stderr.
    ///
    /// Deliberately not a structured event carrying anything about the round:
    /// the only values it prints are the running count and the compiled bucket
    /// width, both of which are public, deployment-wide, and identical for
    /// every client.
    fn record_overrun(&self) {
        let overruns = self.overruns.fetch_add(1, Ordering::Relaxed) + 1;
        let bucket_millis = self.bucket.as_millis();
        eprintln!("private_query_release_overrun={overruns},bucket_millis:{bucket_millis}");
    }
}

impl fmt::Debug for ReleaseSchedule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReleaseSchedule")
            .field("bucket", &self.bucket)
            .field("overruns", &self.overruns())
            .finish()
    }
}

/// One round's release window: a deadline and the schedule that issued it.
pub(super) struct ReleaseWindow<'a> {
    schedule: &'a ReleaseSchedule,
    deadline: Instant,
}

impl ReleaseWindow<'_> {
    /// Runs one round's work inside the bucket.
    ///
    /// `None` is the overrun: the work future has been dropped at the
    /// deadline, and the caller must answer with the uniform refusal. Dropping
    /// it is safe by construction -- a pending response that never reaches an
    /// outbound body poll releases its admission and never borrows its bytes,
    /// which is the same property that makes an abandoned connection safe.
    pub(super) async fn bounded<F>(&self, work: F) -> Option<F::Output>
    where
        F: Future,
    {
        match timeout_at(self.deadline, work).await {
            Ok(finished) => Some(finished),
            Err(_) => {
                self.schedule.record_overrun();
                None
            }
        }
    }

    /// Waits until this round's release deadline.
    ///
    /// Returns immediately once the deadline has passed, so the fail-closed
    /// path writes its refusal at the same instant a completed round would
    /// have written its answer.
    pub(super) async fn release(self) {
        sleep_until(self.deadline).await;
    }
}

impl fmt::Debug for ReleaseWindow<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReleaseWindow { ..REDACTED.. }")
    }
}

#[cfg(test)]
mod tests {
    use std::future::pending;

    use super::*;

    const BUCKET_MILLIS: u64 = 250;

    fn schedule() -> ReleaseSchedule {
        ReleaseSchedule::from_timeout_bucket_millis(BUCKET_MILLIS)
    }

    /// Work that finishes early is still released at the bucket, not when it
    /// finished. `start_paused` makes this exact rather than approximate: the
    /// runtime advances its clock only when every task is idle, so the elapsed
    /// value below is the schedule's arithmetic and not a wall-clock sample.
    #[tokio::test(start_paused = true)]
    async fn early_work_is_released_at_the_bucket_not_at_completion() {
        let schedule = schedule();
        let started = Instant::now();

        let window = schedule.admit();
        let finished = window.bounded(std::future::ready(7u8)).await;
        window.release().await;

        assert_eq!(finished, Some(7));
        assert_eq!(started.elapsed(), Duration::from_millis(BUCKET_MILLIS));
        assert_eq!(schedule.overruns(), 0);
    }

    /// Work that never finishes is cancelled at the bucket and reported, and
    /// the round still releases exactly on schedule rather than late.
    #[tokio::test(start_paused = true)]
    async fn overrunning_work_fails_closed_on_the_same_deadline() {
        let schedule = schedule();
        let started = Instant::now();

        let window = schedule.admit();
        let finished = window.bounded(pending::<u8>()).await;
        window.release().await;

        assert_eq!(finished, None);
        assert_eq!(started.elapsed(), Duration::from_millis(BUCKET_MILLIS));
        assert_eq!(schedule.overruns(), 1);
    }

    /// Two rounds through one schedule accumulate their overruns, so the
    /// operator-visible count is a running total rather than a latch.
    #[tokio::test(start_paused = true)]
    async fn overruns_accumulate_across_rounds() {
        let schedule = schedule();

        for expected in 1..=2 {
            let window = schedule.admit();
            assert!(window.bounded(pending::<u8>()).await.is_none());
            window.release().await;
            assert_eq!(schedule.overruns(), expected);
        }
    }

    #[test]
    fn the_schedule_reports_its_bucket_and_hides_nothing_else() {
        assert_eq!(
            format!("{:?}", schedule()),
            "ReleaseSchedule { bucket: 250ms, overruns: 0 }"
        );
    }

    #[tokio::test]
    async fn a_window_debug_is_redacted() {
        let schedule = schedule();
        assert_eq!(
            format!("{:?}", schedule.admit()),
            "ReleaseWindow { ..REDACTED.. }"
        );
    }
}
