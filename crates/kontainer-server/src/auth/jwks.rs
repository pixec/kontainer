//! Picking the key and algorithm that check a provider-signed token (OIDC ID tokens, robot
//! federation) out of the provider's published key set.

use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Result};
use jsonwebtoken::jwk::{Jwk, JwkSet, KeyAlgorithm};
use jsonwebtoken::{Algorithm, Header};

/// A token naming a key we don't have makes us refetch the key set (keys rotate), at most this
/// often per provider, so such tokens cannot make us hammer it.
pub(crate) const FORCED_REFRESH_COOLDOWN: Duration = Duration::from_secs(60);

/// Asymmetric algorithms accepted when the key does not declare its own.
const ALLOWED: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

/// The key in `set` for a token with `header`: the one its `kid` names or, when it names none,
/// the only key. `Ok(None)` when not (yet) published, which refetching the set may fix.
pub(crate) fn find_key(set: &JwkSet, header: &Header) -> Result<Option<Jwk>> {
    match &header.kid {
        Some(kid) => Ok(set.find(kid).cloned()),
        None if set.keys.len() <= 1 => Ok(set.keys.first().cloned()),
        None => bail!("token has no key id (kid) and the issuer publishes several keys"),
    }
}

/// The algorithm to verify with: the key's declared one, which the token header must agree
/// with; otherwise the header's, if it is an allowed asymmetric algorithm. Never the
/// header's choice alone (no `none`, no HMAC with a public key as the secret).
pub(crate) fn algorithm(jwk: &Jwk, header: &Header) -> Result<Algorithm> {
    let alg = match &jwk.common.key_algorithm {
        Some(declared) => {
            let declared = signing_algorithm(declared).ok_or_else(|| anyhow!("signing key declares unsupported algorithm {declared:?}"))?;
            ensure!(header.alg == declared, "token algorithm {:?} does not match its key's {declared:?}", header.alg);
            declared
        }
        None => header.alg,
    };
    ensure!(ALLOWED.contains(&alg), "token algorithm {alg:?} is not accepted");
    Ok(alg)
}

fn signing_algorithm(k: &KeyAlgorithm) -> Option<Algorithm> {
    Some(match k {
        KeyAlgorithm::RS256 => Algorithm::RS256,
        KeyAlgorithm::RS384 => Algorithm::RS384,
        KeyAlgorithm::RS512 => Algorithm::RS512,
        KeyAlgorithm::PS256 => Algorithm::PS256,
        KeyAlgorithm::PS384 => Algorithm::PS384,
        KeyAlgorithm::PS512 => Algorithm::PS512,
        KeyAlgorithm::ES256 => Algorithm::ES256,
        KeyAlgorithm::ES384 => Algorithm::ES384,
        KeyAlgorithm::EdDSA => Algorithm::EdDSA,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rsa(kid: &str, alg: Option<&str>) -> Jwk {
        let mut v = serde_json::json!({ "kty": "RSA", "kid": kid, "use": "sig", "n": "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw", "e": "AQAB" });
        if let Some(a) = alg {
            v["alg"] = a.into();
        }
        serde_json::from_value(v).unwrap()
    }

    fn header(alg: Algorithm, kid: Option<&str>) -> Header {
        Header { kid: kid.map(str::to_string), ..Header::new(alg) }
    }

    #[test]
    fn key_algorithm_wins_over_header() {
        let k = rsa("a", Some("RS256"));
        assert_eq!(algorithm(&k, &header(Algorithm::RS256, None)).unwrap(), Algorithm::RS256);
        assert!(algorithm(&k, &header(Algorithm::RS512, None)).is_err(), "mismatch");
        assert!(algorithm(&k, &header(Algorithm::HS256, None)).is_err(), "hmac with a public key");
    }

    #[test]
    fn header_algorithm_must_be_asymmetric() {
        let k = rsa("a", None);
        assert_eq!(algorithm(&k, &header(Algorithm::PS256, None)).unwrap(), Algorithm::PS256);
        for alg in [Algorithm::HS256, Algorithm::HS384, Algorithm::HS512] {
            assert!(algorithm(&k, &header(alg, None)).is_err());
        }
        assert!(algorithm(&rsa("a", Some("HS256")), &header(Algorithm::HS256, None)).is_err(), "declared hmac is refused too");
    }

    #[test]
    fn kid_is_required_with_several_keys() {
        let one = JwkSet { keys: vec![rsa("a", None)] };
        let two = JwkSet { keys: vec![rsa("a", None), rsa("b", None)] };
        assert!(find_key(&one, &header(Algorithm::RS256, None)).unwrap().is_some());
        assert!(find_key(&two, &header(Algorithm::RS256, None)).is_err());
        assert_eq!(find_key(&two, &header(Algorithm::RS256, Some("b"))).unwrap().unwrap().common.key_id.as_deref(), Some("b"));
        assert!(find_key(&two, &header(Algorithm::RS256, Some("c"))).unwrap().is_none());
    }
}
