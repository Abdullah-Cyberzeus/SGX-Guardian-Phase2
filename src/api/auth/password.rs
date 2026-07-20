use anyhow::{anyhow, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

const MIN_PASSWORD_LEN: usize = 12;

pub fn validate_policy(password: &str) -> Result<()> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(anyhow!(
            "password must be at least {} characters",
            MIN_PASSWORD_LEN
        ));
    }
    if !password.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(anyhow!("password must include an uppercase letter"));
    }
    if !password.chars().any(|c| c.is_ascii_lowercase()) {
        return Err(anyhow!("password must include a lowercase letter"));
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err(anyhow!("password must include a number"));
    }
    if !password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        return Err(anyhow!("password must include a symbol"));
    }
    Ok(())
}

pub async fn hash_password(password: String) -> Result<String> {
    tokio::task::spawn_blocking(move || {
        validate_policy(&password)?;
        let salt = SaltString::generate(&mut OsRng);
        Ok(Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow!("argon2 hash failed: {}", e))?
            .to_string())
    })
    .await
    .map_err(|e| anyhow!("password hashing task failed: {}", e))?
}

pub async fn verify_password(password: String, encoded_hash: String) -> Result<bool> {
    tokio::task::spawn_blocking(move || {
        let parsed = PasswordHash::new(&encoded_hash)
            .map_err(|e| anyhow!("invalid password hash: {}", e))?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    })
    .await
    .map_err(|e| anyhow!("password verification task failed: {}", e))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_rejects_weak_passwords() {
        assert!(validate_policy("short").is_err());
        assert!(validate_policy("alllowercase123!").is_err());
        assert!(validate_policy("ALLUPPERCASE123!").is_err());
        assert!(validate_policy("NoNumbersHere!").is_err());
        assert!(validate_policy("NoSymbolsHere123").is_err());
    }

    #[tokio::test]
    async fn hash_and_verify_round_trip() {
        let password = "GuardianPass123!".to_string();
        let hash = hash_password(password.clone())
            .await
            .expect("hash password");
        assert!(verify_password(password, hash).await.expect("verify"));
    }
}
