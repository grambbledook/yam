# yam

Yet Another Authorization server. A learning project: building an OAuth 2.1–compliant
authorization server in Go from scratch, then layering on OIDC and persistence.

## Build

Requires Go 1.26+.

```sh
make build        # builds to ./bin/yum
```

Or directly:

```sh
go build -o ./bin/yam .
```

## Run

```sh
./bin/yam --port 8080 --issuer-url http://localhost:8080 --key-path /path/to/key
```

All flags can also be set via environment variables (`PORT`, `ISSUER_URL`, `KEY_PATH`);
flags take precedence.

## Reading list

### Core specs (Phase 1 — read these first)

- [OAuth 2.1 (draft-ietf-oauth-v2-1)](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) —
  **the** spec this project implements. Read the latest draft; verify normative
  language (MUST vs SHOULD) against the draft text, not RFC 6749 habits.
- [RFC 9700 — Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700) —
  the published version of
  [draft-ietf-oauth-security-topics](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics).
  Threat model and mitigations; most of it is folded into 2.1's MUSTs.
- [RFC 7636 — PKCE](https://www.rfc-editor.org/rfc/rfc7636) — mandatory for code flow
  in 2.1; the mechanics live here.
- [RFC 6749 — OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749) — the base framework
  2.1 consolidates. Useful for background; where it conflicts with 2.1, 2.1 wins.
- [RFC 6750 — Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750) — how clients
  present access tokens to resource servers.

### Endpoint-specific (Phase 1)

- [RFC 7662 — Token Introspection](https://www.rfc-editor.org/rfc/rfc7662) — `/introspect`.
- [RFC 7009 — Token Revocation](https://www.rfc-editor.org/rfc/rfc7009) — `/revoke`.
- [RFC 8414 — Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414) —
  the `/.well-known/oauth-authorization-server` discovery document.
- [RFC 9207 — `iss` Authorization Response Parameter](https://www.rfc-editor.org/rfc/rfc9207) —
  mix-up attack mitigation, referenced by 2.1.

### Tokens, keys & signing

- [RFC 7519 — JWT](https://www.rfc-editor.org/rfc/rfc7519)
- [RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens](https://www.rfc-editor.org/rfc/rfc9068)
- [RFC 7515 — JWS](https://www.rfc-editor.org/rfc/rfc7515) and
  [RFC 7517 — JWK](https://www.rfc-editor.org/rfc/rfc7517) — signing and publishing keys
  (`--key-path`, and eventually a `/jwks` endpoint).

### Security hygiene (OWASP)

- [Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) —
  handling signing keys and client secrets.
- [OAuth 2.0 Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html) —
  condensed checklist view of the security BCP.
- [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) —
  hashing client secrets (and user credentials in Phase 2).
- [Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) —
  relevant to the authorization endpoint's consent/login pages.

### Phase 2 — OIDC

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)

### Phase 4 — ReBAC

- [Zanzibar: Google's Consistent, Global Authorization System](https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/) —
  the paper the Phase 4 engine is modeled on.

### Phase 5 — stretch goals (SHOULD/MAY)

- [RFC 9126 — Pushed Authorization Requests (PAR)](https://www.rfc-editor.org/rfc/rfc9126)
- [RFC 8707 — Resource Indicators](https://www.rfc-editor.org/rfc/rfc8707)
- [RFC 7591 — Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591)
- [RFC 9449 — DPoP](https://www.rfc-editor.org/rfc/rfc9449) — sender-constrained tokens.
- [RFC 7523 — JWT Profile for Client Authentication](https://www.rfc-editor.org/rfc/rfc7523) —
  `private_key_jwt`: asymmetric client auth via signed JWT assertions.
- [RFC 8705 — Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://www.rfc-editor.org/rfc/rfc8705) —
  asymmetric client auth at the TLS layer; the other sender-constraining mechanism besides DPoP.
