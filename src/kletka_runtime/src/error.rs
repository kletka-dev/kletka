#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeError {
    #[error("vm '{0}' not found")]
    VmNotFound(String),

    #[error("checkpoint '{0}' not found")]
    CheckpointNotFound(String),

    #[error("vm '{vm}' is not stopped; stop it before {action}")]
    NotStopped { vm: String, action: &'static str },

    #[error("{0}")]
    Failed(String),
}

pub type RuntimeResult<T> = Result<T, RuntimeError>;

impl From<String> for RuntimeError {
    fn from(message: String) -> Self {
        Self::Failed(message)
    }
}

impl From<&str> for RuntimeError {
    fn from(message: &str) -> Self {
        Self::Failed(message.to_string())
    }
}

impl RuntimeError {
    pub fn not_stopped(vm: &str, action: &'static str) -> Self {
        Self::NotStopped {
            vm: vm.to_string(),
            action,
        }
    }

    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::VmNotFound(_) | Self::CheckpointNotFound(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_stay_stable() {
        assert_eq!(
            RuntimeError::VmNotFound("web".into()).to_string(),
            "vm 'web' not found"
        );
        assert_eq!(
            RuntimeError::not_stopped("web", "resizing").to_string(),
            "vm 'web' is not stopped; stop it before resizing"
        );
        assert!(RuntimeError::CheckpointNotFound("clean".into()).is_not_found());
        assert!(!RuntimeError::from("boom").is_not_found());
    }
}
