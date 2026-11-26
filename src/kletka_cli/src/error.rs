use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    NotFound,
    Unauthorized,
    Other,
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct CliError {
    pub kind: ErrorKind,
    pub message: String,
    pub hint: Option<String>,
    pub detail: Option<String>,
}

pub type CliResult<T> = Result<T, CliError>;

impl CliError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Other,
            message: message.into(),
            hint: None,
            detail: None,
        }
    }

    pub fn kind(mut self, kind: ErrorKind) -> Self {
        self.kind = kind;
        self
    }

    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn detail(mut self, detail: impl fmt::Display) -> Self {
        self.detail = Some(detail.to_string());
        self
    }

    pub fn is_not_found(&self) -> bool {
        self.kind == ErrorKind::NotFound
    }

    pub fn render(&self, verbose: bool) -> String {
        let mut out = format!("error: {}", self.message);
        if let Some(hint) = &self.hint {
            out.push_str(&format!("\n  hint: {hint}"));
        }
        match (&self.detail, verbose) {
            (Some(detail), true) => out.push_str(&format!("\n  detail: {detail}")),
            (Some(_), false) => out.push_str("\n  (run with --verbose for details)"),
            (None, _) => {}
        }
        out
    }
}

impl From<String> for CliError {
    fn from(message: String) -> Self {
        Self::new(message)
    }
}

impl From<&str> for CliError {
    fn from(message: &str) -> Self {
        Self::new(message)
    }
}

pub fn io_error(what: impl fmt::Display, err: std::io::Error) -> CliError {
    let message = match err.kind() {
        std::io::ErrorKind::NotFound => format!("{what}: no such file or directory"),
        std::io::ErrorKind::PermissionDenied => format!("{what}: permission denied"),
        _ => format!("{what}: {err}"),
    };
    CliError::new(message).detail(err)
}

pub use kletka_types::error_chain;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_hides_detail_unless_verbose() {
        let err = CliError::new("cannot reach the control plane")
            .hint("check the URL")
            .detail("tcp connect error: Connection refused");
        let quiet = err.render(false);
        assert!(quiet.contains("cannot reach the control plane"));
        assert!(quiet.contains("hint: check the URL"));
        assert!(!quiet.contains("Connection refused"));
        assert!(quiet.contains("--verbose"));
        assert!(err.render(true).contains("Connection refused"));
    }
}
