use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
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
        Router,
        extract::State,
        response::IntoResponse,
        routing::{get, post},
    };
    use serde_json::json;
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::net::TcpListener;

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
            Some("admin@example.com"),
            Some("Admin User"),
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
            Some("admin@example.com"),
            Some("Admin User"),
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

    fn valid_claims() -> IdTokenClaims {
        let now = Utc::now().timestamp();
        IdTokenClaims {
            iss: "https://issuer".into(),
            sub: "cylenium-user".into(),
            aud: Audience::One("sgx-client".into()),
            exp: now + 300,
            iat: Some(now),
            nbf: Some(now - 1),
            email: Some("owner@example.com".into()),
            name: Some("Owner".into()),
            nonce: Some("nonce-1".into()),
        }
    }

    #[test]
    fn accepts_valid_single_and_multiple_audiences() {
        let claims = valid_claims();
        validate_claims(&claims, "https://issuer", "sgx-client", " nonce-1 ")
            .expect("single audience");

        let mut claims = claims;
        claims.aud = Audience::Many(vec!["another-client".into(), "sgx-client".into()]);
        validate_claims(&claims, "https://issuer", "sgx-client", "nonce-1").expect("audience list");
    }

    #[test]
    fn rejects_invalid_claim_timing_and_identity_fields() {
        let now = Utc::now().timestamp();
        let cases = [
            ("missing expected nonce", {
                let claims = valid_claims();
                (claims, "https://issuer", "sgx-client", "")
            }),
            ("issuer mismatch", {
                let claims = valid_claims();
                (claims, "https://other", "sgx-client", "nonce-1")
            }),
            ("audience mismatch", {
                let claims = valid_claims();
                (claims, "https://issuer", "other-client", "nonce-1")
            }),
        ];
        for (expected, (claims, issuer, audience, nonce)) in cases {
            let error = validate_claims(&claims, issuer, audience, nonce).expect_err(expected);
            assert!(error.to_string().contains(expected), "{error}");
        }

        let mut expired = valid_claims();
        expired.exp = now;
        assert!(
            validate_claims(&expired, "https://issuer", "sgx-client", "nonce-1")
                .expect_err("expired")
                .to_string()
                .contains("expired")
        );

        let mut future_iat = valid_claims();
        future_iat.iat = Some(now + IAT_FUTURE_LEEWAY_SECS + 1);
        future_iat.exp = now + 600;
        assert!(
            validate_claims(&future_iat, "https://issuer", "sgx-client", "nonce-1")
                .expect_err("future iat")
                .to_string()
                .contains("iat is in the future")
        );

        let mut reversed_times = valid_claims();
        reversed_times.exp = now + 30;
        reversed_times.iat = Some(now + 30);
        assert!(
            validate_claims(&reversed_times, "https://issuer", "sgx-client", "nonce-1")
                .expect_err("iat after exp")
                .to_string()
                .contains("before exp")
        );

        let mut future_nbf = valid_claims();
        future_nbf.nbf = Some(now + 120);
        assert!(
            validate_claims(&future_nbf, "https://issuer", "sgx-client", "nonce-1")
                .expect_err("future nbf")
                .to_string()
                .contains("not yet valid")
        );

        let mut blank_nonce = valid_claims();
        blank_nonce.nonce = Some("  ".into());
        assert!(
            validate_claims(&blank_nonce, "https://issuer", "sgx-client", "nonce-1")
                .expect_err("blank nonce")
                .to_string()
                .contains("missing nonce")
        );
    }

    fn test_jwk(kid: Option<&str>, alg: Option<&str>) -> Jwk {
        Jwk {
            kty: "EC".into(),
            kid: kid.map(str::to_string),
            alg: alg.map(str::to_string),
            crv: Some("P-256".into()),
            x: Some(URL_SAFE_NO_PAD.encode([0u8; 32])),
            y: Some(URL_SAFE_NO_PAD.encode([0u8; 32])),
            n: None,
            e: None,
        }
    }

    #[test]
    fn selects_exact_key_and_rejects_missing_or_ambiguous_keys() {
        let header = JwtHeader {
            alg: "ES256".into(),
            kid: Some("key-2".into()),
            typ: Some("JWT".into()),
        };
        let jwks = Jwks {
            keys: vec![
                test_jwk(Some("key-1"), Some("ES256")),
                test_jwk(Some("key-2"), None),
            ],
        };
        assert_eq!(
            select_jwk(&jwks, &header)
                .expect("matching key")
                .kid
                .as_deref(),
            Some("key-2")
        );

        let missing = JwtHeader {
            kid: Some("missing".into()),
            ..header
        };
        assert!(
            select_jwk(&jwks, &missing)
                .expect_err("missing key")
                .to_string()
                .contains("not found")
        );

        let ambiguous_header = JwtHeader {
            alg: "ES256".into(),
            kid: None,
            typ: None,
        };
        let ambiguous = Jwks {
            keys: vec![test_jwk(None, None), test_jwk(None, Some("ES256"))],
        };
        assert!(
            select_jwk(&ambiguous, &ambiguous_header)
                .expect_err("ambiguous key")
                .to_string()
                .contains("ambiguous")
        );
    }

    #[test]
    fn rejects_unsupported_or_malformed_signing_keys() {
        let mut ec = test_jwk(Some("key"), Some("ES256"));
        assert!(
            verify_signature(&ec, "HS256", b"input", b"signature")
                .expect_err("unsupported algorithm")
                .to_string()
                .contains("unsupported")
        );

        ec.crv = Some("P-384".into());
        assert!(
            verify_signature(&ec, "ES256", b"input", b"signature")
                .expect_err("unsupported curve")
                .to_string()
                .contains("curve")
        );

        ec.crv = Some("P-256".into());
        ec.x = None;
        assert!(
            verify_signature(&ec, "ES256", b"input", b"signature")
                .expect_err("missing x")
                .to_string()
                .contains("missing jwk x")
        );

        ec.x = Some(URL_SAFE_NO_PAD.encode([0u8; 31]));
        assert!(
            verify_signature(&ec, "ES256", b"input", b"signature")
                .expect_err("short coordinate")
                .to_string()
                .contains("coordinate length")
        );

        ec.x = Some(URL_SAFE_NO_PAD.encode([0u8; 32]));
        assert!(
            verify_signature(&ec, "ES256", b"input", b"bad")
                .expect_err("invalid signature")
                .to_string()
                .contains("signature verification failed")
        );

        let rsa = Jwk {
            kty: "RSA".into(),
            kid: None,
            alg: Some("RS256".into()),
            crv: None,
            x: None,
            y: None,
            n: Some(URL_SAFE_NO_PAD.encode([1u8; 256])),
            e: Some(URL_SAFE_NO_PAD.encode([1u8, 0, 1])),
        };
        assert!(
            verify_signature(&rsa, "RS256", b"input", b"bad")
                .expect_err("invalid rsa signature")
                .to_string()
                .contains("signature verification failed")
        );
    }

    #[test]
    fn rejects_malformed_unsigned_and_mismatched_jwts() {
        let empty = Jwks { keys: vec![] };
        for (token, expected) in [
            ("header.claims", "missing jwt signature"),
            ("a.b.c.d", "too many segments"),
        ] {
            assert!(
                verify_id_token_with_jwks(token, &empty, "issuer", "client", "nonce")
                    .expect_err(expected)
                    .to_string()
                    .contains(expected)
            );
        }

        let claims = URL_SAFE_NO_PAD.encode(b"{}");
        let unsigned_header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let unsigned = format!("{unsigned_header}.{claims}.");
        assert!(
            verify_id_token_with_jwks(&unsigned, &empty, "issuer", "client", "nonce")
                .expect_err("unsigned")
                .to_string()
                .contains("unsigned")
        );

        let wrong_type_header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"JWE"}"#);
        let wrong_type = format!("{wrong_type_header}.{claims}.AA");
        assert!(
            verify_id_token_with_jwks(&wrong_type, &empty, "issuer", "client", "nonce")
                .expect_err("wrong type")
                .to_string()
                .contains("jwt typ")
        );

        let keyed_header =
            URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"JWT","kid":"missing"}"#);
        let missing_key = format!("{keyed_header}.{claims}.AA");
        assert!(
            verify_id_token_with_jwks(&missing_key, &empty, "issuer", "client", "nonce")
                .expect_err("missing key")
                .to_string()
                .contains("matching jwk not found")
        );
    }

    #[test]
    fn decodes_jwk_parts_and_reports_invalid_values() {
        assert_eq!(
            decode_jwk_part(Some("AQID"), "x").expect("decode"),
            vec![1, 2, 3]
        );
        assert!(
            decode_jwk_part(None, "x")
                .expect_err("missing")
                .to_string()
                .contains("missing jwk x")
        );
        assert!(
            decode_jwk_part(Some("!"), "x")
                .expect_err("invalid")
                .to_string()
                .contains("invalid jwk x")
        );
    }

    #[test]
    fn form_encoding_escapes_values() {
        assert_eq!(
            form_urlencoded(&[("redirect_uri", "https://sgx.example/cb?a=1&b=2")]),
            "redirect_uri=https%3A%2F%2Fsgx.example%2Fcb%3Fa%3D1%26b%3D2"
        );
        assert_eq!(percent_encode("A z/~"), "A+z%2F~");
    }

    #[test]
    fn constructs_clients_with_an_injected_http_client() {
        let config = CyleniumOidcConfig {
            issuer: "https://issuer".into(),
            token_endpoint: "https://issuer/token".into(),
            jwks_uri: "https://issuer/jwks".into(),
            client_id: "client".into(),
            client_secret: None,
            redirect_uri: "https://guardian/callback".into(),
        };
        let client = CyleniumOidcClient::with_http_client(config.clone(), reqwest::Client::new());
        assert_eq!(client.config.client_id, config.client_id);
        assert!(client.config.client_secret.is_none());
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
        email: Option<&str>,
        name: Option<&str>,
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
            "email": email,
            "name": name
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
