//! Passkeys (WebAuthn), with [`webauthn_rs`]: registration from a signed-in session, and
//! sign-in by username or with a discoverable credential (no username).
//!
//! The relying party is the registry's public URL: its host is the RP id, the URL itself the
//! only allowed origin. A ceremony's state lives in `webauthn_challenges` between its start and
//! finish requests, which may reach different instances; each is used once and expires after
//! [`CHALLENGE_TTL`].
//!
//! Passkeys require user verification (a PIN or biometric on the authenticator), so a passkey
//! sign-in is two factors on its own: it needs no one-time code, even for accounts with TOTP on.

use anyhow::{Context, Result};
use sha2::Digest as _;
use webauthn_rs::prelude::{
    CreationChallengeResponse, DiscoverableAuthentication, DiscoverableKey, Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Url, Uuid, Webauthn, WebauthnBuilder,
};

/// How long a started ceremony may be finished.
pub const CHALLENGE_TTL: chrono::Duration = chrono::Duration::minutes(5);

pub struct Passkeys {
    webauthn: Webauthn,
    /// Keys the WebAuthn user handle of each account to this instance's secret, so handles
    /// stored on authenticators reveal nothing about account ids.
    handle_key: [u8; 32],
}

impl Passkeys {
    /// The relying party for `public_url`. Fails when its host is not a domain name (WebAuthn
    /// needs one: `localhost` works, an IP address does not).
    pub fn new(public_url: &str, rp_name: &str, secret: &[u8]) -> Result<Self> {
        let origin = Url::parse(public_url).with_context(|| format!("server.public_url {public_url} is not a URL"))?;
        let rp_id = origin.domain().with_context(|| format!("passkeys need server.public_url to name a host by domain, not {public_url}"))?.to_string();
        let webauthn = WebauthnBuilder::new(&rp_id, &origin)
            .context("passkey relying party")?
            .rp_name(rp_name)
            .build()
            .context("passkey relying party")?;
        let mut h = sha2::Sha256::new();
        h.update(b"kontainer webauthn user handle\0");
        h.update(secret);
        Ok(Self { webauthn, handle_key: h.finalize().into() })
    }

    /// The WebAuthn user handle of account `user_id`: stable, opaque.
    pub fn user_handle(&self, user_id: i64) -> Uuid {
        let mut h = sha2::Sha256::new();
        h.update(self.handle_key);
        h.update(user_id.to_be_bytes());
        let d = h.finalize();
        let mut b = [0u8; 16];
        b.copy_from_slice(&d[..16]);
        Uuid::from_bytes(b)
    }

    /// Start registering a passkey for `user_id`, excluding the credentials it already has.
    /// Returns the options for `navigator.credentials.create` and the state to keep.
    pub fn start_registration(&self, user_id: i64, username: &str, display_name: &str, existing: &[Passkey]) -> Result<(serde_json::Value, String)> {
        let exclude = existing.iter().map(|p| p.cred_id().clone()).collect::<Vec<_>>();
        let (ccr, state): (CreationChallengeResponse, PasskeyRegistration) = self.webauthn.start_passkey_registration(self.user_handle(user_id), username, display_name, (!exclude.is_empty()).then_some(exclude))?;
        let mut options = serde_json::to_value(&ccr)?;
        // Ask for a discoverable credential where the authenticator can make one, so the passkey
        // also signs in without a username; one that cannot is still fine.
        if let Some(sel) = options.pointer_mut("/publicKey/authenticatorSelection").and_then(|v| v.as_object_mut()) {
            sel.insert("residentKey".into(), "preferred".into());
            sel.insert("requireResidentKey".into(), false.into());
        }
        Ok((options, serde_json::to_string(&state)?))
    }

    pub fn finish_registration(&self, state: &str, credential: &RegisterPublicKeyCredential) -> Result<Passkey> {
        let state: PasskeyRegistration = serde_json::from_str(state).context("reading the registration state")?;
        Ok(self.webauthn.finish_passkey_registration(credential, &state)?)
    }

    /// Start a sign-in with `creds` (a known account's passkeys) or, without any, with whatever
    /// discoverable credential the authenticator offers. Returns the options for
    /// `navigator.credentials.get`, the ceremony kind and the state to keep.
    pub fn start_login(&self, creds: &[Passkey]) -> Result<(serde_json::Value, &'static str, String)> {
        if creds.is_empty() {
            let (mut rcr, state): (RequestChallengeResponse, DiscoverableAuthentication) = self.webauthn.start_discoverable_authentication()?;
            // A button press opens the browser's passkey dialog: not conditional (autofill) UI.
            rcr.mediation = None;
            return Ok((serde_json::to_value(&rcr)?, "discoverable", serde_json::to_string(&state)?));
        }
        let (rcr, state): (RequestChallengeResponse, PasskeyAuthentication) = self.webauthn.start_passkey_authentication(creds)?;
        Ok((serde_json::to_value(&rcr)?, "login", serde_json::to_string(&state)?))
    }

    /// The user handle and credential id a discoverable sign-in's response names.
    pub fn identify<'a>(&self, credential: &'a PublicKeyCredential) -> Result<(Uuid, &'a [u8])> {
        Ok(self.webauthn.identify_discoverable_authentication(credential)?)
    }

    /// Verify a sign-in against `passkey` (the one the response names). On success, returns the
    /// passkey with its counter and backup state brought up to date, whether that changed
    /// anything, and the new signature counter.
    pub fn finish_login(&self, kind: &str, state: &str, credential: &PublicKeyCredential, passkey: &Passkey) -> Result<(Passkey, bool, u32)> {
        let result = match kind {
            "discoverable" => {
                let state: DiscoverableAuthentication = serde_json::from_str(state).context("reading the sign-in state")?;
                self.webauthn.finish_discoverable_authentication(credential, state, &[DiscoverableKey::from(passkey)])?
            }
            _ => {
                let state: PasskeyAuthentication = serde_json::from_str(state).context("reading the sign-in state")?;
                self.webauthn.finish_passkey_authentication(credential, &state)?
            }
        };
        if !result.user_verified() {
            anyhow::bail!("the authenticator did not verify the user");
        }
        if result.cred_id().as_ref() != passkey.cred_id().as_ref() {
            anyhow::bail!("the response is for another credential");
        }
        let mut updated = passkey.clone();
        let changed = updated.update_credential(&result).unwrap_or(false);
        Ok((updated, changed, result.counter()))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn user_handles_are_stable_and_keyed() {
        let a = super::Passkeys::new("http://registry.test", "kontainer", b"one").unwrap();
        let b = super::Passkeys::new("http://registry.test", "kontainer", b"two").unwrap();
        assert_eq!(a.user_handle(7), a.user_handle(7));
        assert_ne!(a.user_handle(7), a.user_handle(8));
        assert_ne!(a.user_handle(7), b.user_handle(7), "keyed to the instance secret");
        assert!(super::Passkeys::new("http://10.0.0.1:5000", "kontainer", b"x").is_err(), "an IP address is no RP id");
    }
}
