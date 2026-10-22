//! The runner protocol: JSON over HTTP under `/api/v1/runner`.
//!
//! 1. `POST /claim` with the runner's token. The registry hands out the next queued build of a
//!    namespace the runner serves, with a token for that build only.
//! 2. `GET /builds/{id}`: the [`BuildSpec`].
//! 3. `POST /builds/{id}/log` every couple of seconds with what the log gained since the last
//!    acknowledged offset ([`CheckIn`]): the check-in. The reply ([`CheckInReply`]) says how much
//!    of the log the server has, so a runner whose reply got lost resends from there, and whether
//!    to stop (cancelled, or failed by the server).
//! 4. `POST /builds/{id}/commit` once the checkout is done; the server picks the tags.
//! 5. `PUT /builds/{id}/image` with the OCI archive; the server imports it and the build
//!    succeeds. Or `POST /builds/{id}/finish` to report a failure.
//!
//! A runner that starts the build somewhere else (a container, a Kubernetes Job) hands the build
//! token to it, and sends `POST /builds/{id}/heartbeat` while it starts up.

use serde::{Deserialize, Serialize};

/// Where the protocol lives on the server.
pub const BASE: &str = "/api/v1/runner";

/// Everything a runner needs to build, and nothing more.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildSpec {
    pub id: i64,
    pub repository: String,
    pub git_url: String,
    #[serde(default)]
    pub git_username: Option<String>,
    /// For private repositories.
    #[serde(default)]
    pub git_token: Option<crate::WireSecret>,
    /// What was asked for (branch, tag or commit), for the log.
    pub git_ref: String,
    /// What to fetch: the pinned commit from a webhook, else `git_ref`.
    pub target: String,
    pub dockerfile: String,
    pub context: String,
    /// The build is stopped after this long.
    pub timeout_secs: u64,
}

/// Sent with every claim: what the runner is, for its page in the UI.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClaimRequest {
    /// The machine or pod, e.g. its host name.
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub version: String,
    /// `local`, `docker` or `kubernetes`.
    #[serde(default)]
    pub executor: String,
    #[serde(default)]
    pub concurrency: usize,
    /// Builds it is running now.
    #[serde(default)]
    pub running: usize,
    /// Busy: just reporting in, don't hand out a build.
    #[serde(default)]
    pub report_only: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claimed {
    pub id: i64,
    /// Bearer token for this build's endpoints; valid while it runs.
    pub token: crate::WireSecret,
}

/// Most of a truncated log's end that is kept (see [`CheckIn::tail`]).
pub const LOG_TAIL_BYTES: usize = 64 << 10;

/// A check-in: the log from byte `offset` on. The server appends `data` when `offset` is the
/// length it has (see [`CheckInReply::length`]) and ignores it otherwise.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CheckIn {
    /// Bytes of the log the server already has (the last [`CheckInReply::length`]).
    #[serde(default)]
    pub offset: u64,
    /// What the log gained since, possibly nothing (a plain heartbeat).
    #[serde(default)]
    pub data: String,
    /// The end of a log the server truncated: the last bytes of it (at most [`LOG_TAIL_BYTES`]),
    /// `offset` being where they start. Accepted once, with an `offset` past what was stored;
    /// what lies between is counted as omitted.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tail: bool,
    /// Runners before chunked logs sent the whole log here instead; the server takes what it
    /// lacks of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CheckInReply {
    /// Stop now: report `cancelled` (or just exit if the build is already over).
    pub stop: bool,
    /// Bytes of the log the server has (stored, or dropped past its size limit): where the next
    /// check-in starts.
    #[serde(default)]
    pub length: u64,
    /// The log reached the server's size limit: send no more until the build ends, then just its
    /// last [`LOG_TAIL_BYTES`] with `tail`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Commit {
    pub sha: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CommitReply {
    pub tags: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Finish {
    /// `failed` or `cancelled`.
    pub status: String,
    pub message: String,
    /// A last line for the log, from a runner that has no log of its own for the build (it
    /// failed to start it). A runner with a log checks its end in first instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<String>,
    /// Runners before chunked logs sent the whole log here; the server takes what it lacks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImageReply {
    /// e.g. `Pushed acme/api as main and latest (sha256:0123...)`.
    pub summary: String,
}
