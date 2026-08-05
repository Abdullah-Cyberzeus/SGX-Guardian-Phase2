# Cylenium OIDC integration

The frontend uses Authorization Code with PKCE through the SG-X backend. The browser never receives the Cognito client secret, refresh token, PKCE verifier, or raw ID token.

## Registered redirect URI

Register this exact URI for each deployed frontend origin:

```text
https://<sgx-frontend-origin>/auth/cylenium/callback
```

For local development with the current Vite configuration:

```text
http://localhost:3000/auth/cylenium/callback
```

Production must use HTTPS. URI matching is exact, including port and trailing slash.

## Backend contract

### `GET /auth/cylenium/login`

Query parameters:

- `redirectUri`: one of the backend's allow-listed callback URIs
- `returnTo`: an allow-listed app-relative path, such as `/home`

The backend must generate `state`, a nonce, and a PKCE verifier/challenge; store the verifier and state in a short-lived, encrypted, `HttpOnly`, `Secure`, `SameSite=Lax` cookie or server-side session; then redirect to Cognito's authorize endpoint with `response_type=code`, `code_challenge_method=S256`, and scopes `openid profile email`.

### `POST /auth/cylenium/callback`

Request:

```json
{
  "code": "authorization-code",
  "state": "opaque-state",
  "redirectUri": "https://<sgx-frontend-origin>/auth/cylenium/callback"
}
```

The backend must validate state, redeem the code with the saved PKCE verifier and confidential client credentials, and validate the ID token using the discovery document/JWKS. Pin the expected issuer and `RS256`; validate signature, `aud`, `exp`, `iat`, and nonce. Use `(iss, sub)` as the stable external identity key. Do not key users by email.

Return the same application-session shape used by `/auth/login`:

```json
{
  "token": "sgx-application-bearer-token",
  "expiresAt": 1785780000,
  "user": {
    "id": "internal-user-id",
    "email": "user@example.com",
    "name": "Example User"
  }
}
```

The returned token must be an SG-X application session, not the Cognito ID token. In a future server-rendered deployment, prefer an `HttpOnly` session cookie over browser token storage.

## Cognito configuration

Keep the Cognito discovery URL, exact issuer, client ID, client secret, and allowed callback origins in backend configuration. Store the client secret in AWS Secrets Manager and retrieve it at runtime. None of these values—especially the secret—belong in `VITE_*` variables.
