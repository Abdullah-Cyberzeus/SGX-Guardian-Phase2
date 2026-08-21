use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use reqwest::header;
use ring::signature::{self, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

const IAT_FUTURE_LEEWAY_SECS: i64 = 60;

#[derive(Debug, Clone)]
pub struct CyleniumOidcConfig {
    pub issuer: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
}

#[derive(Debug, Clone)]
pub struct CyleniumOidcClient {
    http: reqwest::Client,
    config: CyleniumOidcConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct TokenResponse {
    pub access_token: Option<String>,
    pub id_token: String,
    pub token_type: Option<String>,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Audience,
    pub exp: i64,
    #[serde(default)]
    pub iat: Option<i64>,
    #[serde(default)]
    pub nbf: Option<i64>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Audience {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    typ: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

impl CyleniumOidcClient {
    pub fn new(config: CyleniumOidcConfig) -> Self {
        Self {
            http: reqwest::Client::new(),
            config,
        }
    }

    pub fn with_http_client(config: CyleniumOidcConfig, http: reqwest::Client) -> Self {
        Self { http, config }
    }

    pub async fn exchange_code(
        &self,
        code: &str,
        code_verifier: Option<&str>,
    ) -> Result<TokenResponse> {
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.config.redirect_uri.as_str()),
            ("client_id", self.config.client_id.as_str()),
        ];
        if let Some(secret) = self.config.client_secret.as_deref() {
            form.push(("client_secret", secret));
        }
        if let Some(verifier) = code_verifier {
            form.push(("code_verifier", verifier));
        }

        let body = form_urlencoded(&form);
        let response = self
            .http
            .post(&self.config.token_endpoint)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await?
            .error_for_status()?;

        response.json::<TokenResponse>().await.map_err(Into::into)
    }

    pub async fn verify_id_token(
        &self,
        id_token: &str,
        expected_nonce: &str,
    ) -> Result<IdTokenClaims> {
        let jwks = self.fetch_jwks().await?;
        verify_id_token_with_jwks(
            id_token,
            &jwks,
            &self.config.issuer,
            &self.config.client_id,
            expected_nonce,
        )
    }

    pub async fn exchange_code_and_verify(
        &self,
        code: &str,
        code_verifier: Option<&str>,
        expected_nonce: &str,
    ) -> Result<(TokenResponse, IdTokenClaims)> {
        let token = self.exchange_code(code, code_verifier).await?;
        let claims = self
            .verify_id_token(&token.id_token, expected_nonce)
            .await?;
        Ok((token, claims))
    }

    async fn fetch_jwks(&self) -> Result<Jwks> {
        self.http
            .get(&self.config.jwks_uri)
            .send()
            .await?
            .error_for_status()?
            .json::<Jwks>()
            .await
            .map_err(Into::into)
    }
}

fn verify_id_token_with_jwks(
    id_token: &str,
    jwks: &Jwks,
    expected_issuer: &str,
    expected_audience: &str,
    expected_nonce: &str,
) -> Result<IdTokenClaims> {
    let mut parts = id_token.split('.');
    let encoded_header = parts.next().ok_or_else(|| anyhow!("missing jwt header"))?;
    let encoded_claims = parts.next().ok_or_else(|| anyhow!("missing jwt claims"))?;
    let encoded_sig = parts
        .next()
        .ok_or_else(|| anyhow!("missing jwt signature"))?;
    if parts.next().is_some() {
        return Err(anyhow!("jwt has too many segments"));
    }

    let header_bytes = URL_SAFE_NO_PAD.decode(encoded_header)?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes)?;
    if header.typ.as_deref().is_some_and(|typ| typ != "JWT") {
        return Err(anyhow!("unsupported jwt typ"));
    }
    if header.alg == "none" {
        return Err(anyhow!("unsigned id token rejected"));
    }

    let jwk = select_jwk(jwks, &header)?;
    let signing_input = format!("{}.{}", encoded_header, encoded_claims);
    let signature = URL_SAFE_NO_PAD.decode(encoded_sig)?;
    verify_signature(jwk, &header.alg, signing_input.as_bytes(), &signature)?;

    let claims_bytes = URL_SAFE_NO_PAD.decode(encoded_claims)?;
    let claims: IdTokenClaims = serde_json::from_slice(&claims_bytes)?;
    validate_claims(&claims, expected_issuer, expected_audience, expected_nonce)?;
    Ok(claims)
}

fn select_jwk<'a>(jwks: &'a Jwks, header: &JwtHeader) -> Result<&'a Jwk> {
    let matches: Vec<&Jwk> = jwks
        .keys
        .iter()
        .filter(|jwk| {
            header
                .kid
                .as_ref()
                .is_none_or(|kid| jwk.kid.as_ref() == Some(kid))
                && jwk.alg.as_ref().is_none_or(|alg| alg == &header.alg)
        })
        .collect();

    match matches.as_slice() {
        [jwk] => Ok(jwk),
        [] => Err(anyhow!("matching jwk not found")),
        _ => Err(anyhow!("ambiguous jwk match")),
    }
}

fn verify_signature(jwk: &Jwk, alg: &str, signing_input: &[u8], sig: &[u8]) -> Result<()> {
    match (alg, jwk.kty.as_str()) {
        ("ES256", "EC") => {
            if jwk.crv.as_deref() != Some("P-256") {
                return Err(anyhow!("unsupported ec curve"));
            }
            let x = decode_jwk_part(jwk.x.as_deref(), "x")?;
            let y = decode_jwk_part(jwk.y.as_deref(), "y")?;
            if x.len() != 32 || y.len() != 32 {
                return Err(anyhow!("invalid p-256 jwk coordinate length"));
            }
            let mut public_key = Vec::with_capacity(65);
            public_key.push(0x04);
            public_key.extend_from_slice(&x);
            public_key.extend_from_slice(&y);
            let key = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, public_key);
            key.verify(signing_input, sig)
                .map_err(|_| anyhow!("id token signature verification failed"))
        }
        ("RS256", "RSA") => {
            let n = decode_jwk_part(jwk.n.as_deref(), "n")?;
            let e = decode_jwk_part(jwk.e.as_deref(), "e")?;
            signature::RsaPublicKeyComponents { n: &n, e: &e }
                .verify(&signature::RSA_PKCS1_2048_8192_SHA256, signing_input, sig)
                .map_err(|_| anyhow!("id token signature verification failed"))
        }
        _ => Err(anyhow!("unsupported id token alg or key type")),
    }
}

fn validate_claims(
    claims: &IdTokenClaims,
    expected_issuer: &str,
    expected_audience: &str,
    expected_nonce: &str,
) -> Result<()> {
    let expected_nonce = expected_nonce.trim();
    if expected_nonce.is_empty() {
        return Err(anyhow!("missing expected nonce"));
    }
    if claims.iss != expected_issuer {
        return Err(anyhow!("id token issuer mismatch"));
    }
    if !claims.aud.contains(expected_audience) {
        return Err(anyhow!("id token audience mismatch"));
    }

    let now = Utc::now().timestamp();
    if claims.exp <= now {
        return Err(anyhow!("id token expired"));
    }
    let iat = claims.iat.ok_or_else(|| anyhow!("id token missing iat"))?;
    if iat > now + IAT_FUTURE_LEEWAY_SECS {
        return Err(anyhow!("id token iat is in the future"));
    }
    if iat >= claims.exp {
        return Err(anyhow!("id token iat must be before exp"));
    }
    if claims.nbf.is_some_and(|nbf| nbf > now) {
        return Err(anyhow!("id token not yet valid"));
    }
    let nonce = claims
        .nonce
        .as_deref()
        .map(str::trim)
        .filter(|nonce| !nonce.is_empty())
        .ok_or_else(|| anyhow!("id token missing nonce"))?;
    if nonce != expected_nonce {
        return Err(anyhow!("id token nonce mismatch"));
    }
    Ok(())
}

impl Audience {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(aud) => aud == expected,
            Self::Many(audiences) => audiences.iter().any(|aud| aud == expected),
        }
    }
}

fn decode_jwk_part(value: Option<&str>, name: &str) -> Result<Vec<u8>> {
    let value = value.ok_or_else(|| anyhow!("missing jwk {}", name))?;
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|e| anyhow!("invalid jwk {}: {}", name, e))
}

fn form_urlencoded(values: &[(&str, &str)]) -> String {
    values
        .iter()
        .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn percent_encode(value: &str) -> String {
    value.bytes().fold(String::new(), |mut encoded, byte| {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char)
            }
            b' ' => encoded.push('+'),
            _ => encoded.push_str(&format!("%{:02X}", byte)),
        }
        encoded
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::auth::ecdsa::normalize_p256_signature;
    use crate::key_manager::KeyManager;
    use axum::{
        extract::State,
        response::IntoResponse,
        routing::{get, post},
        Router,
    };
    use serde_json::json;
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::net::TcpListener;

    struct SignedIdTokenClaims<'a> {
        email: Option<&'a str>,
        name: Option<&'a str>,
    }

    #[tokio::test]
    async fn exchanges_code_and_verifies_es256_id_token() {
        let td = TempDir::new().expect("tempdir");
        let signer = Arc::new(
            KeyManager::load_or_generate(td.path().join("idp.key").to_str().expect("path"))
                .expect("signer"),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let issuer = format!("http://{}", listener.local_addr().expect("addr"));
        let id_token = signed_id_token(
            signer.clone(),
            "kid-1",
            &issuer,
            "sgx-client",
            "cylenium-user-1",
            "nonce-1",
            SignedIdTokenClaims {
                email: Some("admin@example.com"),
                name: Some("Admin User"),
            },
        )
        .await;
        let jwks = jwks_for_signer(signer, "kid-1");
        let app = Router::new()
            .route("/token", post(token_handler))
            .route("/jwks", get(jwks_handler))
            .with_state(MockState { id_token, jwks });
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let client = CyleniumOidcClient::new(CyleniumOidcConfig {
            issuer: issuer.clone(),
            token_endpoint: format!("{}/token", issuer),
            jwks_uri: format!("{}/jwks", issuer),
            client_id: "sgx-client".into(),
            client_secret: Some("secret".into()),
            redirect_uri: "https://sgx.example/callback".into(),
        });
        let (token, claims) = client
            .exchange_code_and_verify("auth-code", Some("verifier"), "nonce-1")
            .await
            .expect("exchange and verify");

        handle.abort();
        assert_eq!(token.access_token.as_deref(), Some("access-token"));
        assert_eq!(claims.sub, "cylenium-user-1");
        assert_eq!(claims.email.as_deref(), Some("admin@example.com"));
        assert_eq!(claims.name.as_deref(), Some("Admin User"));
    }

    #[tokio::test]
    async fn rejects_wrong_audience() {
        let td = TempDir::new().expect("tempdir");
        let signer = Arc::new(
            KeyManager::load_or_generate(td.path().join("idp.key").to_str().expect("path"))
                .expect("signer"),
        );
        let issuer = "https://issuer";
        let id_token = signed_id_token(
            signer.clone(),
            "kid-1",
            issuer,
            "sgx-client",
            "cylenium-user-1",
            "nonce-1",
            SignedIdTokenClaims {
                email: Some("admin@example.com"),
                name: Some("Admin User"),
            },
        )
        .await;
        let jwks: Jwks = serde_json::from_value(jwks_for_signer(signer, "kid-1")).expect("jwks");

        let err = verify_id_token_with_jwks(&id_token, &jwks, issuer, "other", "nonce-1")
            .expect_err("wrong audience must fail");
        assert!(err.to_string().contains("audience mismatch"));
    }

    #[test]
    fn rejects_missing_nonce_claim() {
        let now = Utc::now().timestamp();
        let claims = IdTokenClaims {
            iss: "https://issuer".into(),
            sub: "subject".into(),
            aud: Audience::One("sgx-client".into()),
            exp: now + 300,
            iat: Some(now),
            nbf: None,
            email: None,
            name: None,
            nonce: None,
        };

        let err = validate_claims(&claims, "https://issuer", "sgx-client", "nonce-1")
            .expect_err("missing nonce must fail");
        assert!(err.to_string().contains("missing nonce"));
    }

    #[test]
    fn rejects_nonce_mismatch() {
        let now = Utc::now().timestamp();
        let claims = IdTokenClaims {
            iss: "https://issuer".into(),
            sub: "subject".into(),
            aud: Audience::One("sgx-client".into()),
            exp: now + 300,
            iat: Some(now),
            nbf: None,
            email: None,
            name: None,
            nonce: Some("nonce-2".into()),
        };

        let err = validate_claims(&claims, "https://issuer", "sgx-client", "nonce-1")
            .expect_err("nonce mismatch must fail");
        assert!(err.to_string().contains("nonce mismatch"));
    }

    #[test]
    fn rejects_missing_iat() {
        let now = Utc::now().timestamp();
        let claims = IdTokenClaims {
            iss: "https://issuer".into(),
            sub: "subject".into(),
            aud: Audience::One("sgx-client".into()),
            exp: now + 300,
            iat: None,
            nbf: None,
            email: None,
            name: None,
            nonce: Some("nonce-1".into()),
        };

        let err = validate_claims(&claims, "https://issuer", "sgx-client", "nonce-1")
            .expect_err("missing iat must fail");
        assert!(err.to_string().contains("missing iat"));
    }

    #[test]
    fn form_encoding_escapes_values() {
        assert_eq!(
            form_urlencoded(&[("redirect_uri", "https://sgx.example/cb?a=1&b=2")]),
            "redirect_uri=https%3A%2F%2Fsgx.example%2Fcb%3Fa%3D1%26b%3D2"
        );
    }

    #[derive(Clone)]
    struct MockState {
        id_token: String,
        jwks: serde_json::Value,
    }

    async fn token_handler(State(state): State<MockState>, body: String) -> impl IntoResponse {
        assert!(body.contains("grant_type=authorization_code"));
        assert!(body.contains("code=auth-code"));
        assert!(body.contains("client_secret=secret"));
        assert!(body.contains("code_verifier=verifier"));
        axum::Json(json!({
            "access_token": "access-token",
            "id_token": state.id_token,
            "token_type": "Bearer",
            "expires_in": 300
        }))
    }

    async fn jwks_handler(State(state): State<MockState>) -> impl IntoResponse {
        axum::Json(state.jwks)
    }

    async fn signed_id_token(
        signer: Arc<KeyManager>,
        kid: &str,
        issuer: &str,
        audience: &str,
        subject: &str,
        nonce: &str,
        claims: SignedIdTokenClaims<'_>,
    ) -> String {
        let header = json!({ "alg": "ES256", "typ": "JWT", "kid": kid });
        let now = Utc::now().timestamp();
        let claims = json!({
            "iss": issuer,
            "sub": subject,
            "aud": audience,
            "iat": now,
            "exp": now + 300,
            "nonce": nonce,
            "email": claims.email,
            "name": claims.name
        });
        let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header"));
        let encoded_claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims"));
        let signing_input = format!("{}.{}", encoded_header, encoded_claims);
        let signing_bytes = signing_input.as_bytes().to_vec();
        let signature = tokio::task::spawn_blocking(move || signer.sign(&signing_bytes))
            .await
            .expect("join")
            .expect("sign");
        let signature = normalize_p256_signature(&signature).expect("raw signature");
        format!("{}.{}", signing_input, URL_SAFE_NO_PAD.encode(signature))
    }

    fn jwks_for_signer(signer: Arc<KeyManager>, kid: &str) -> serde_json::Value {
        let public_key = signer.pubkey_der().expect("pubkey");
        assert_eq!(public_key.len(), 65);
        json!({
            "keys": [{
                "kty": "EC",
                "kid": kid,
                "alg": "ES256",
                "crv": "P-256",
                "x": URL_SAFE_NO_PAD.encode(&public_key[1..33]),
                "y": URL_SAFE_NO_PAD.encode(&public_key[33..65])
            }]
        })
    }
}
