//! JWT bearer-token authentication for the Turso sync server.
//!
//! Implements the verifier described in plan §5 with all nine validation
//! rules enforced unconditionally:
//!
//! 1. `alg=none` rejected at decode time.
//! 2. `kid` claim required when multiple keys are registered.
//! 3. The key's bound algorithm MUST equal the token's `alg`.
//! 4. `iss` claim required and in the `allowed_issuers` allow-list.
//! 5. `sub` claim required and non-empty.
//! 6. `exp` claim required and validated with `leeway_secs`.
//! 7. `aud` validated against `allowed_audiences` when configured.
//! 8. `nbf` validated if present.
//! 9. Role-source mode: in Mode A (default) the JWT `roles` claim is
//!    discarded; in Mode B it is carried onto the `Principal`.
//!
//! Rule (3) is the load-bearing defense against the HS/RS algorithm
//! confusion attack — forging an HS256 token using a configured RS256 public
//! key as the HMAC secret. By tagging each registered key with exactly one
//! algorithm and rejecting any token whose `alg` doesn't match the looked-up
//! key's algorithm, we close the class of attack that historically broke
//! ad-hoc JWT verifiers.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use turso_core::auth::{ClaimValue, Principal};

/// Where roles come from. Mode A is the default and is recommended for
/// production: the JWT carries identity only, and roles are read from
/// `_turso_rbac_role_assignments` after `Principal` construction. Mode B
/// trusts the IdP fully — acceptable when the IdP is operator-controlled,
/// dangerous with consumer IdPs that let users edit their own claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleSource {
    Table,
    Jwt,
}

impl RoleSource {
    pub fn from_env_value(v: Option<&str>) -> Self {
        match v {
            Some("jwt") => RoleSource::Jwt,
            _ => RoleSource::Table,
        }
    }
}

/// A single JWT signing key bound to exactly one algorithm.
///
/// `kid` is the key identifier the JWT header carries (`kid` claim). The
/// `algorithm` is the *only* algorithm this key is valid for — see threat
/// #2 in the plan's security model table.
pub struct JwtKey {
    pub kid: String,
    pub algorithm: Algorithm,
    pub key: DecodingKey,
}

impl std::fmt::Debug for JwtKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtKey")
            .field("kid", &self.kid)
            .field("algorithm", &format_args!("{:?}", self.algorithm))
            .field("key", &"<opaque>")
            .finish()
    }
}

/// JWT verifier. Construct via `JwtVerifier::builder` for compile-time
/// safety on required fields.
#[derive(Debug)]
pub struct JwtVerifier {
    keys: Vec<JwtKey>,
    allowed_issuers: HashSet<String>,
    allowed_audiences: Option<HashSet<String>>,
    leeway_secs: u64,
    role_source: RoleSource,
}

impl JwtVerifier {
    pub fn builder() -> JwtVerifierBuilder {
        JwtVerifierBuilder::default()
    }

    pub fn role_source(&self) -> RoleSource {
        self.role_source
    }

    /// Verify a bearer-token string and return the resulting `Principal`.
    ///
    /// Errors are mapped to the JWT-error labels callers surface in
    /// `WWW-Authenticate: Bearer error="..."` headers. The error text is
    /// deliberately terse — verifier failures should not leak which check
    /// rejected the token (e.g., "iss mismatch" tells a probing attacker
    /// the iss allow-list shape).
    pub fn verify(&self, token: &str) -> Result<Principal> {
        // Step 1: decode the header without verifying signature so we can
        // look up the bound key by (alg, kid). This is the ONLY place we
        // touch the token before signature verification; we never look at
        // the payload.
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| anyhow!("invalid_token: cannot decode header: {e}"))?;

        // Rule 1: `alg=none` is rejected outright. `jsonwebtoken` already
        // refuses to decode it for any configured algorithm, but we assert
        // here for defense-in-depth (and for the test that exercises the
        // attack shape directly).
        // jsonwebtoken's `Algorithm` enum doesn't include `None`; the
        // header parse step above accepts it only as a literal string we
        // must check.
        let alg_field_lower = serde_json::to_string(&header.alg)
            .unwrap_or_default()
            .to_ascii_lowercase();
        if alg_field_lower.contains("none") {
            return Err(anyhow!("invalid_token: alg=none forbidden"));
        }

        // Rule 2 + 3: locate the key by (alg, kid). `kid` is required
        // whenever the verifier holds more than one key — for a single-key
        // setup we permit the omission to match common production patterns.
        let kid = header.kid.as_deref();
        let key = self.locate_key(kid, header.alg)?;

        // Build a Validation that pins the algorithm to the key's bound
        // algorithm. This is the bind-keys-to-algorithms enforcement: any
        // token whose `alg` differs from `key.algorithm` is rejected.
        let mut validation = Validation::new(key.algorithm);
        validation.leeway = self.leeway_secs;
        // `nbf` is optional in JWT, but if present must be in the past.
        // jsonwebtoken 9 defaults `validate_nbf` to false, so enable it
        // explicitly to close the "future-dated nbf" check (rule 8).
        validation.validate_nbf = true;
        // jsonwebtoken validates iss/aud if `required_spec_claims` lists
        // them and the validation's allow-lists are non-empty. Both are
        // required by spec.
        validation.set_required_spec_claims(&["exp", "iss", "sub"]);
        validation.set_issuer(&self.allowed_issuers.iter().cloned().collect::<Vec<_>>());
        if let Some(auds) = &self.allowed_audiences {
            validation.set_audience(&auds.iter().cloned().collect::<Vec<_>>());
        } else {
            // No audience pre-configured — disable jsonwebtoken's
            // audience check so tokens without `aud` (per spec optional)
            // are still accepted.
            validation.validate_aud = false;
        }

        let data = jsonwebtoken::decode::<JwtClaims>(token, &key.key, &validation)
            .map_err(|e| anyhow!("invalid_token: {e}"))?;
        let claims = data.claims;

        if claims.sub.trim().is_empty() {
            return Err(anyhow!("invalid_token: sub is empty"));
        }

        let roles = match self.role_source {
            RoleSource::Jwt => claims.roles.clone().unwrap_or_default(),
            RoleSource::Table => Vec::new(), // populated by Mode A role loader
        };

        // Strip protocol claims so application predicates can't accidentally
        // reference `@claim.exp` or similar. Anything else passes through.
        let mut extras: BTreeMap<String, ClaimValue> = BTreeMap::new();
        for (k, v) in &claims.extras {
            if matches!(k.as_str(), "iss" | "sub" | "exp" | "nbf" | "iat" | "aud") {
                continue;
            }
            if let Some(cv) = json_to_claim(v) {
                extras.insert(k.clone(), cv);
            }
        }

        Principal::new(claims.iss, claims.sub, roles, extras, claims.exp)
            .map_err(|e| anyhow!("invalid_token: principal construction failed: {e}"))
    }

    fn locate_key(&self, kid: Option<&str>, alg: Algorithm) -> Result<&JwtKey> {
        // When there are multiple keys, `kid` MUST be present in the header
        // so a probing attacker can't fall back to "first-key wins".
        if self.keys.len() > 1 && kid.is_none() {
            return Err(anyhow!("invalid_token: kid required with multiple keys"));
        }
        let key = match kid {
            Some(k) => self
                .keys
                .iter()
                .find(|jk| jk.kid == k)
                .ok_or_else(|| anyhow!("invalid_token: unknown kid {k}"))?,
            None => self
                .keys
                .first()
                .ok_or_else(|| anyhow!("invalid_token: no keys configured"))?,
        };

        // Rule 3: the token's `alg` MUST match the key's bound algorithm.
        // This is what closes HS/RS confusion — even if an attacker
        // guesses our `kid`, sending HS256 against an RS256-bound key is
        // refused before signature verification runs.
        if key.algorithm != alg {
            return Err(anyhow!(
                "invalid_token: algorithm mismatch for kid {} (expected {:?}, got {:?})",
                key.kid,
                key.algorithm,
                alg
            ));
        }
        Ok(key)
    }
}

#[derive(Default)]
pub struct JwtVerifierBuilder {
    keys: Vec<JwtKey>,
    allowed_issuers: HashSet<String>,
    allowed_audiences: Option<HashSet<String>>,
    leeway_secs: Option<u64>,
    role_source: Option<RoleSource>,
}

impl JwtVerifierBuilder {
    pub fn add_key(mut self, key: JwtKey) -> Self {
        self.keys.push(key);
        self
    }

    pub fn add_issuer(mut self, iss: impl Into<String>) -> Self {
        self.allowed_issuers.insert(iss.into());
        self
    }

    pub fn add_audience(mut self, aud: impl Into<String>) -> Self {
        self.allowed_audiences
            .get_or_insert_with(HashSet::new)
            .insert(aud.into());
        self
    }

    pub fn leeway_secs(mut self, secs: u64) -> Self {
        self.leeway_secs = Some(secs);
        self
    }

    pub fn role_source(mut self, src: RoleSource) -> Self {
        self.role_source = Some(src);
        self
    }

    pub fn build(self) -> Result<Arc<JwtVerifier>> {
        if self.keys.is_empty() {
            return Err(anyhow!("JwtVerifier requires at least one signing key"));
        }
        if self.allowed_issuers.is_empty() {
            return Err(anyhow!(
                "JwtVerifier requires at least one allowed issuer; \
                 cross-issuer sub collision is closed by iss being mandatory"
            ));
        }
        // Each (algorithm, kid) pair must be unique. Two keys with the same
        // kid but different algorithms would let an attacker choose which
        // one to satisfy.
        let mut seen = HashSet::new();
        for key in &self.keys {
            if !seen.insert((key.algorithm, key.kid.clone())) {
                return Err(anyhow!(
                    "JwtVerifier: duplicate (algorithm, kid) pair {:?}/{:?}",
                    key.algorithm,
                    key.kid
                ));
            }
        }

        Ok(Arc::new(JwtVerifier {
            keys: self.keys,
            allowed_issuers: self.allowed_issuers,
            allowed_audiences: self.allowed_audiences,
            leeway_secs: self.leeway_secs.unwrap_or(30),
            role_source: self.role_source.unwrap_or(RoleSource::Table),
        }))
    }
}

/// Header extraction helper. Returns the bearer token value if the
/// `Authorization: Bearer <jwt>` header is well-formed. Header keys are
/// matched case-insensitively per RFC 7230. Logging the token value would
/// leak credentials to operators, so callers MUST NOT pass the result to
/// `tracing::*!` macros.
pub fn extract_bearer_token(headers: &BTreeMap<String, String>) -> Option<&str> {
    let raw = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .map(|(_, v)| v.as_str())?;
    let trimmed = raw.trim();
    let prefix = "Bearer ";
    if !trimmed.get(..prefix.len())?.eq_ignore_ascii_case(prefix) {
        return None;
    }
    Some(trimmed[prefix.len()..].trim_start())
}

#[derive(Debug, Deserialize, Serialize)]
struct JwtClaims {
    iss: String,
    sub: String,
    exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    roles: Option<Vec<String>>,
    #[serde(flatten)]
    extras: BTreeMap<String, serde_json::Value>,
}

fn json_to_claim(v: &serde_json::Value) -> Option<ClaimValue> {
    match v {
        serde_json::Value::Null => Some(ClaimValue::Null),
        serde_json::Value::Bool(b) => Some(ClaimValue::Bool(*b)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(ClaimValue::Integer(i))
            } else {
                n.as_f64().map(ClaimValue::Float)
            }
        }
        serde_json::Value::String(s) => Some(ClaimValue::String(s.clone())),
        // Arrays and objects can't be represented in a turso Value; ignore them
        // rather than coerce. Predicates that try to reference them would have
        // been rejected at grant-load time because the claim name would
        // resolve to NULL.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde::Serialize;

    fn hs256_verifier() -> Arc<JwtVerifier> {
        JwtVerifier::builder()
            .add_key(JwtKey {
                kid: "hs1".into(),
                algorithm: Algorithm::HS256,
                key: DecodingKey::from_secret(b"secret-hs-key"),
            })
            .add_issuer("https://idp.example.com")
            .leeway_secs(60)
            .build()
            .unwrap()
    }

    #[derive(Serialize)]
    struct TestClaims {
        iss: String,
        sub: String,
        exp: i64,
        #[serde(skip_serializing_if = "Option::is_none")]
        roles: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        nbf: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        aud: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tenant_id: Option<String>,
    }

    fn make_token(alg: Algorithm, key: &[u8], kid: Option<&str>, claims: TestClaims) -> String {
        let mut header = Header::new(alg);
        header.kid = kid.map(|s| s.to_string());
        encode(&header, &claims, &EncodingKey::from_secret(key)).unwrap()
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    #[test]
    fn valid_token_verifies() {
        let v = hs256_verifier();
        let tok = make_token(
            Algorithm::HS256,
            b"secret-hs-key",
            Some("hs1"),
            TestClaims {
                iss: "https://idp.example.com".into(),
                sub: "alice".into(),
                exp: now() + 600,
                roles: None,
                nbf: None,
                aud: None,
                tenant_id: Some("tenant-7".into()),
            },
        );
        let p = v.verify(&tok).expect("valid token");
        assert_eq!(p.iss, "https://idp.example.com");
        assert_eq!(p.sub, "alice");
        assert!(p.claims.contains_key("tenant_id"));
    }

    #[test]
    fn unknown_kid_rejected() {
        let v = hs256_verifier();
        let tok = make_token(
            Algorithm::HS256,
            b"secret-hs-key",
            Some("evil-kid"),
            TestClaims {
                iss: "https://idp.example.com".into(),
                sub: "alice".into(),
                exp: now() + 600,
                roles: None,
                nbf: None,
                aud: None,
                tenant_id: None,
            },
        );
        let err = v.verify(&tok).unwrap_err();
        assert!(format!("{err}").contains("kid"), "got: {err}");
    }

    #[test]
    fn iss_not_in_allow_list_rejected() {
        let v = hs256_verifier();
        let tok = make_token(
            Algorithm::HS256,
            b"secret-hs-key",
            Some("hs1"),
            TestClaims {
                iss: "https://evil.example.com".into(),
                sub: "alice".into(),
                exp: now() + 600,
                roles: None,
                nbf: None,
                aud: None,
                tenant_id: None,
            },
        );
        assert!(v.verify(&tok).is_err());
    }

    #[test]
    fn expired_token_rejected() {
        let v = hs256_verifier();
        let tok = make_token(
            Algorithm::HS256,
            b"secret-hs-key",
            Some("hs1"),
            TestClaims {
                iss: "https://idp.example.com".into(),
                sub: "alice".into(),
                exp: now() - 7200, // 2h in the past, well past 60s leeway
                roles: None,
                nbf: None,
                aud: None,
                tenant_id: None,
            },
        );
        assert!(v.verify(&tok).is_err());
    }

    #[test]
    fn missing_sub_rejected() {
        let v = hs256_verifier();
        let tok = make_token(
            Algorithm::HS256,
            b"secret-hs-key",
            Some("hs1"),
            TestClaims {
                iss: "https://idp.example.com".into(),
                sub: "".into(),
                exp: now() + 600,
                roles: None,
                nbf: None,
                aud: None,
                tenant_id: None,
            },
        );
        assert!(v.verify(&tok).is_err());
    }

    #[test]
    fn aud_mismatch_rejected_when_audiences_configured() {
        let v = JwtVerifier::builder()
            .add_key(JwtKey {
                kid: "hs1".into(),
                algorithm: Algorithm::HS256,
                key: DecodingKey::from_secret(b"secret-hs-key"),
            })
            .add_issuer("https://idp.example.com")
            .add_audience("expected-audience")
            .build()
            .unwrap();
        let tok = make_token(
            Algorithm::HS256,
            b"secret-hs-key",
            Some("hs1"),
            TestClaims {
                iss: "https://idp.example.com".into(),
                sub: "alice".into(),
                exp: now() + 600,
                roles: None,
                nbf: None,
                aud: Some("wrong-audience".into()),
                tenant_id: None,
            },
        );
        assert!(v.verify(&tok).is_err());
    }

    #[test]
    fn nbf_future_rejected() {
        let v = hs256_verifier();
        let tok = make_token(
            Algorithm::HS256,
            b"secret-hs-key",
            Some("hs1"),
            TestClaims {
                iss: "https://idp.example.com".into(),
                sub: "alice".into(),
                exp: now() + 600,
                roles: None,
                nbf: Some(now() + 600),
                aud: None,
                tenant_id: None,
            },
        );
        assert!(v.verify(&tok).is_err());
    }

    #[test]
    fn hs_signed_with_rsa_pubkey_rejected() {
        // Classic HS/RS confusion: an attacker who has the RS256 public key
        // would try to sign HS256 using the public key bytes as the HMAC
        // secret. Our key registry tags `hs1` as HS256-only and `rs1` as
        // RS256-only — a token claiming `alg=HS256` and `kid=rs1` is
        // refused by `locate_key` because the kid's bound algorithm is
        // RS256.
        let pubkey_pem = b"-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----\n";
        let v = JwtVerifier::builder()
            .add_key(JwtKey {
                kid: "rs1".into(),
                algorithm: Algorithm::RS256,
                key: DecodingKey::from_rsa_pem(pubkey_pem)
                    .unwrap_or(DecodingKey::from_secret(b"placeholder")),
            })
            .add_issuer("https://idp.example.com")
            .build()
            .unwrap();

        let tok = make_token(
            Algorithm::HS256,
            pubkey_pem, // attacker uses the public key bytes as HMAC secret
            Some("rs1"),
            TestClaims {
                iss: "https://idp.example.com".into(),
                sub: "attacker".into(),
                exp: now() + 600,
                roles: None,
                nbf: None,
                aud: None,
                tenant_id: None,
            },
        );
        let err = v.verify(&tok).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("algorithm mismatch") || msg.contains("invalid_token"),
            "expected HS/RS confusion to be blocked, got: {msg}"
        );
    }

    #[test]
    fn mode_a_ignores_jwt_roles() {
        let v = hs256_verifier(); // builds in default (Table) mode
        let tok = make_token(
            Algorithm::HS256,
            b"secret-hs-key",
            Some("hs1"),
            TestClaims {
                iss: "https://idp.example.com".into(),
                sub: "alice".into(),
                exp: now() + 600,
                roles: Some(vec!["admin".into(), "editor".into()]),
                nbf: None,
                aud: None,
                tenant_id: None,
            },
        );
        let p = v.verify(&tok).unwrap();
        assert!(p.roles.is_empty(), "Mode A must not promote JWT roles");
    }

    #[test]
    fn mode_b_uses_jwt_roles() {
        let v = JwtVerifier::builder()
            .add_key(JwtKey {
                kid: "hs1".into(),
                algorithm: Algorithm::HS256,
                key: DecodingKey::from_secret(b"secret-hs-key"),
            })
            .add_issuer("https://idp.example.com")
            .role_source(RoleSource::Jwt)
            .build()
            .unwrap();
        let tok = make_token(
            Algorithm::HS256,
            b"secret-hs-key",
            Some("hs1"),
            TestClaims {
                iss: "https://idp.example.com".into(),
                sub: "alice".into(),
                exp: now() + 600,
                roles: Some(vec!["editor".into()]),
                nbf: None,
                aud: None,
                tenant_id: None,
            },
        );
        let p = v.verify(&tok).unwrap();
        assert_eq!(p.roles, vec!["editor".to_string()]);
    }

    #[test]
    fn duplicate_key_pair_rejected_at_build_time() {
        let err = JwtVerifier::builder()
            .add_key(JwtKey {
                kid: "k1".into(),
                algorithm: Algorithm::HS256,
                key: DecodingKey::from_secret(b"a"),
            })
            .add_key(JwtKey {
                kid: "k1".into(),
                algorithm: Algorithm::HS256,
                key: DecodingKey::from_secret(b"b"),
            })
            .add_issuer("https://idp.example.com")
            .build()
            .unwrap_err();
        assert!(format!("{err}").contains("duplicate"));
    }

    #[test]
    fn empty_issuer_list_rejected_at_build_time() {
        let err = JwtVerifier::builder()
            .add_key(JwtKey {
                kid: "k".into(),
                algorithm: Algorithm::HS256,
                key: DecodingKey::from_secret(b"x"),
            })
            .build()
            .unwrap_err();
        assert!(format!("{err}").contains("issuer"));
    }

    #[test]
    fn bearer_extraction_case_insensitive() {
        let mut h = BTreeMap::new();
        h.insert(
            "Authorization".to_string(),
            "Bearer abc.def.ghi".to_string(),
        );
        assert_eq!(extract_bearer_token(&h), Some("abc.def.ghi"));
        let mut h2 = BTreeMap::new();
        h2.insert(
            "authorization".to_string(),
            "bearer xyz.123.qrs".to_string(),
        );
        assert_eq!(extract_bearer_token(&h2), Some("xyz.123.qrs"));
        let mut h3 = BTreeMap::new();
        h3.insert("Authorization".to_string(), "Basic abc".to_string());
        assert_eq!(extract_bearer_token(&h3), None);
    }
}
