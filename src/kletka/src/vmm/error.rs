#[derive(Debug, thiserror::Error)]
pub enum FirecrackerError {
    #[error("could not perform filesystem operation: {0}")]
    Io(#[from] std::io::Error),

    #[error("could not (de)serialize data: {0}")]
    Json(#[from] serde_json::Error),

    #[error("firecracker API request failed ({status}): {body}")]
    Api { status: u16, body: String },

    #[error("missing required binary: {0}")]
    MissingBinary(String),

    #[error("timed out waiting for {0}")]
    Timeout(String),

    #[error("{0}")]
    Other(String),
}
