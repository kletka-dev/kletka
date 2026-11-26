use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash};

pub fn hash(password: &str) -> Result<String, String> {
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|e| format!("hash failed: {e}"))
}

pub fn verify(password: &str, stored: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

pub fn dummy_verify(password: &str) -> bool {
    const DUMMY: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$RdescudvCvvMl5Z7NnMlwQ";
    verify(password, DUMMY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_wrong() {
        let hash = hash("correct horse").unwrap();
        assert!(verify("correct horse", &hash));
        assert!(!verify("wrong", &hash));
        assert!(!verify("x", "not-a-hash"));
    }
}
