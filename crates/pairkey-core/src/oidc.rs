//! Bounded RS256 ID-token profile. Cryptography uses ring; identity/time claims use
//! strict typed decoding and an injected clock. No token-controlled key URLs.
use crate::Error;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use pairkey_types::approval::{Binding, Identity};
use serde::Deserialize;

pub const MAX_JWKS_BYTES: usize = 64 * 1024;
pub const MAX_JWKS_AGE: i64 = 300;

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}
#[derive(Deserialize)]
struct Jwk {
    kty: String,
    kid: String,
    alg: Option<String>,
    #[serde(rename = "use")]
    usage: Option<String>,
    key_ops: Option<Vec<String>>,
    n: Option<String>,
    e: Option<String>,
}
struct RsaKey {
    kid: String,
    modulus: Vec<u8>,
    exponent: Vec<u8>,
}

/// Construct only from the issuer/audience configured by the operator and a JWKS
/// response obtained over authenticated HTTPS at its configured endpoint.
pub struct TrustedIssuer {
    issuer: String,
    audience: String,
    fetched_at: i64,
    keys: Vec<RsaKey>,
}
impl TrustedIssuer {
    pub fn from_jwks(
        issuer: String,
        audience: String,
        bytes: &[u8],
        fetched_at: i64,
    ) -> Result<Self, Error> {
        if !issuer.starts_with("https://")
            || issuer.len() > 256
            || audience.is_empty()
            || audience.len() > 256
            || bytes.len() > MAX_JWKS_BYTES
            || fetched_at < 0
        {
            return Err(Error::Authorization);
        }
        let jwks: Jwks = serde_json::from_slice(bytes).map_err(|_| Error::Authorization)?;
        if jwks.keys.is_empty() || jwks.keys.len() > 32 {
            return Err(Error::Authorization);
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut keys = Vec::new();
        for key in jwks.keys {
            if key.kid.is_empty() || key.kid.len() > 128 || !ids.insert(key.kid.clone()) {
                return Err(Error::Authorization);
            }
            if key.kty != "RSA"
                || key.alg.as_ref().is_some_and(|a| a != "RS256")
                || key.usage.as_ref().is_some_and(|u| u != "sig")
                || key
                    .key_ops
                    .as_ref()
                    .is_some_and(|ops| ops.as_slice() != ["verify"])
            {
                continue;
            }
            let modulus = decode(key.n.as_deref().ok_or(Error::Authorization)?)?;
            let exponent = decode(key.e.as_deref().ok_or(Error::Authorization)?)?;
            // This deployment profile accepts 2048–4096 bit RSA signing keys, e=65537.
            if !(256..=512).contains(&modulus.len())
                || modulus[0] & 0x80 == 0
                || exponent != [1, 0, 1]
            {
                return Err(Error::Authorization);
            }
            keys.push(RsaKey {
                kid: key.kid,
                modulus,
                exponent,
            });
        }
        if keys.is_empty() {
            return Err(Error::Authorization);
        }
        Ok(Self {
            issuer,
            audience,
            fetched_at,
            keys,
        })
    }
    pub fn matches(&self, identity: &Identity) -> bool {
        matches!(identity, Identity::Oidc { issuer,audience,.. } if issuer==&self.issuer && audience==&self.audience)
    }
    pub fn is_fresh(&self, now: i64) -> bool {
        self.fetched_at <= now && now.saturating_sub(self.fetched_at) < MAX_JWKS_AGE
    }

    pub fn verify(
        &self,
        identity: &Identity,
        binding: &Binding,
        token: &str,
        request_expires_at: i64,
        now: i64,
    ) -> Result<(), Error> {
        let Identity::Oidc {
            issuer,
            audience,
            subject,
        } = identity
        else {
            return Err(Error::Authorization);
        };
        if !self.matches(identity) || !self.is_fresh(now) || token.len() > 16 * 1024 {
            return Err(Error::Authorization);
        }
        let parts: Vec<_> = token.split('.').collect();
        if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
            return Err(Error::Authorization);
        }
        let header: Header =
            serde_json::from_slice(&decode(parts[0])?).map_err(|_| Error::Authorization)?;
        if header.alg != "RS256"
            || header.typ.as_ref().is_some_and(|t| t != "JWT")
            || header.kid.len() > 128
        {
            return Err(Error::Authorization);
        }
        let key = self
            .keys
            .iter()
            .find(|k| k.kid == header.kid)
            .ok_or(Error::Authorization)?;
        let signature = decode(parts[2])?;
        let signed_length = parts[0].len() + 1 + parts[1].len();
        ring::signature::RsaPublicKeyComponents {
            n: &key.modulus,
            e: &key.exponent,
        }
        .verify(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            &token.as_bytes()[..signed_length],
            &signature,
        )
        .map_err(|_| Error::Authorization)?;
        let claims: Claims =
            serde_json::from_slice(&decode(parts[1])?).map_err(|_| Error::Authorization)?;
        let audiences = match claims.aud {
            Audience::One(a) => vec![a],
            Audience::Many(a) => a,
        };
        if &claims.iss != issuer
            || &claims.sub != subject
            || audiences.is_empty()
            || audiences.len() > 8
            || !audiences.contains(audience)
            || audiences.iter().any(|a| a.is_empty() || a.len() > 256)
            || (audiences.len() > 1 && claims.azp.as_ref() != Some(audience))
            || claims.azp.as_ref().is_some_and(|a| a != audience)
            || claims.nonce != URL_SAFE_NO_PAD.encode(binding.challenge())
            || claims.iat < binding.issued_at
            || claims.iat > now
            || claims.exp <= now
            || claims.exp <= claims.iat
            || claims.exp < request_expires_at
            || claims
                .nbf
                .is_some_and(|n| n < 0 || n > now || n >= claims.exp)
        {
            return Err(Error::Authorization);
        }
        Ok(())
    }
}
fn decode(value: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| Error::Authorization)
}

// Extensions, critical headers and URLs are deliberately unsupported. Thumbprints
// may accompany a kid, but never select or supply a verification key.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    kid: String,
    typ: Option<String>,
    #[serde(rename = "x5t")]
    _x5t: Option<String>,
    #[serde(rename = "x5t#S256")]
    _x5t_s256: Option<String>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}
#[derive(Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: Audience,
    nonce: String,
    iat: i64,
    exp: i64,
    #[serde(default, deserialize_with = "present")]
    nbf: Option<i64>,
    #[serde(default, deserialize_with = "present")]
    azp: Option<String>,
}

// Missing optional claims are allowed. Present null/mistyped claims are errors.
fn present<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

#[cfg(test)]
mod tests;
