# Sign-in: passkeys, LDAP, organization SSO and keyless robots

Kontainer has local accounts (passwords, two-factor, passkeys, access tokens, robots) and three
ways to use identities kept elsewhere:

- **LDAP / Active Directory:** directory passwords, with groups mapped to roles and teams.
- **OpenID Connect:** one provider for the whole instance (`[auth.oidc]`, see the README), plus
  one per organization.
- **Keyless robots:** CI jobs sign in with the OIDC token their platform issues, so no robot
  password is stored in CI.

All three can keep **synced teams** up to date: a team linked to a directory or provider
group gains and loses members as people sign in.

## Passkeys

People can sign in to the web UI with a passkey (WebAuthn): their device's screen lock, a
password manager, or a security key. Add one under **Settings → Security → Passkeys**: give it a
name and confirm on the device. The same page lists your passkeys, with when each was added and
last used, and removes them.

On the sign-in page, **Sign in with a passkey** works two ways:

- With a username typed in, that account's passkeys are offered.
- With the field empty, the browser offers whatever passkey it has for this registry
  (a discoverable credential), and that passkey names the account.

What to know:

- **Relying party.** The RP id is the host of `server.public_url` and the only accepted origin
  is `public_url` itself. Passkeys are bound to that host: changing the public hostname makes
  existing passkeys stop working. Browsers allow passkeys only on `https://` origins and on
  `http://localhost`. When `public_url` names the registry by IP address, passkeys are off and
  the server logs why.
- **Passkeys count as two factors.** Registration and sign-in require user verification (a PIN
  or biometric on the device), so a passkey sign-in asks for no one-time code, even when the
  account has TOTP on.
- **Same protections as passwords.** Failed passkey sign-ins count toward the brute-force
  lockout, per account and per address. A locked-out or disabled account can't sign in with a
  passkey. Robots can't have passkeys.
- **Command-line tools are unchanged.** `docker login` still needs an access token (or a
  password when two-factor is off).
- **Storage.** A passkey stores only public key material (`passkeys` table). Each ceremony's
  state is kept in `webauthn_challenges` between its two requests, so start and finish can reach
  different instances. A ceremony works once and expires after five minutes.

API (the UI uses these; the JSON options are what `navigator.credentials` takes, with binary
fields as base64url):

| Endpoint | |
| --- | --- |
| `POST /api/v1/auth/passkeys/register/start` `{"name"}` | browser session only; returns `challenge_id` and `options` |
| `POST /api/v1/auth/passkeys/register/finish` `{"challenge_id", "credential"}` | stores the passkey |
| `GET /api/v1/auth/passkeys` | your passkeys |
| `DELETE /api/v1/auth/passkeys/{id}` | removes one of yours |
| `POST /api/v1/auth/passkeys/login/start` `{"username"?}` | without a username (or for an unknown one): a discoverable challenge |
| `POST /api/v1/auth/passkeys/login/finish` `{"challenge_id", "credential"}` | starts a session, like a password sign-in |

## Session cookie

The web UI's session cookie, `kontainer_session`, is `HttpOnly`, `SameSite=Strict`, and
`Secure` when `public_url` is `https://`. No request started from another site carries it:
not a link, not a form, not a top-level navigation.

Single sign-on still works. The provider's redirect back to `/auth/oidc/.../callback` is a
cross-site navigation, so it arrives without the session cookie. That doesn't matter for
signing in, because the callback creates the session. The browser then loads `/...`, and the
page's own API calls are same-site, so they carry the new cookie.

Two short-lived cookies cover the callback, both `HttpOnly`, `SameSite=Lax`,
`Path=/auth/oidc`, `Max-Age=900` and `Secure` on https:

- `kontainer_oidc` binds every SSO login to the browser that started it, which prevents login
  CSRF. A callback without it is refused.
- `kontainer_oidc_link` is set only when a signed-in user starts **Link account**, which is a
  JSON `POST` that needs the session. Only its hash is stored, with the login state and the
  user. At the callback it stands in for the session, for that one link: the identity is linked
  to the user who started it, and only from that browser. Both cookies are cleared when the
  callback answers.

## LDAP

```toml
[auth.ldap]
enabled = true
url = "ldaps://ldap.example.com:636"    # or ldap://...:389 with start_tls = true
start_tls = false
bind_dn = "cn=kontainer,ou=services,dc=example,dc=com"   # empty: anonymous bind
bind_password = "..."
user_base_dn = "ou=people,dc=example,dc=com"
user_filter = "(uid={username})"        # Active Directory: "(sAMAccountName={username})"
username_attr = "uid"
email_attr = "mail"
name_attr = "cn"
group_base_dn = "ou=groups,dc=example,dc=com"   # empty: read the user's memberOf instead
group_filter = "(|(member={dn})(memberUid={username}))"
group_name_attr = "cn"
default_roles = []
[auth.ldap.group_roles]
registry-admins = ["system"]
developers = ["readers"]
```

How sign-in works:

1. Kontainer binds with the service account, finds the user with `user_filter`, then binds as
   that user with the password they typed. Empty passwords are refused.
2. The first sign-in creates an account. Its email and full name come from the directory.
3. On every sign-in, the user's groups are looked up and `group_roles` is applied.
   - Roles named in the mapping are added or removed to match the user's groups.
   - Roles granted by hand are left alone.
   - A user removed from a directory group loses that role at their next sign-in.

LDAP is only tried for accounts without a local password. Local accounts, including the
bootstrap admin, keep working if the directory is down. Directory users can `docker login`
with their directory password unless they turned on two-factor; with two-factor on, they need
an access token.

`{username}` and `{dn}` are escaped before they go into a filter.

## Organization single sign-on

An organization can bring its own OpenID Connect provider (**Organization → Settings → Single
sign-on**, or `PUT /api/v1/orgs/{org}/sso`):

```json
{ "issuer": "https://login.acme.com", "client_id": "kontainer", "client_secret": "...",
  "display_name": "Acme SSO", "groups_claim": "groups" }
```

- Register `https://registry.example.com/auth/oidc/orgs/{org}/callback` as the redirect URI at
  the provider. The settings page shows the exact URL.
- Saving checks the provider's discovery document. The client secret is never returned, and
  leaving it empty on an update keeps the stored one.
- Members sign in at `/auth/oidc/orgs/{org}/login`, or from the sign-in page's organization
  SSO link, where they type the organization's name.

Kontainer doesn't trust an organization's provider to say who someone is:

- **New identities always get a new account.** If the username is taken, a number is
  appended. A provider that claims `admin` cannot sign in as the instance admin.
- **To use an existing account**, sign in normally, then use **Settings → Security → Link
  account** next to that organization. This goes through the provider and records the link.
- Accounts created this way get no instance roles. Their access comes from the organization's
  teams.

## Synced teams

A team can follow one group (**Organization → Teams → Sync**, or
`PUT /api/v1/orgs/{org}/teams/{team}/sync` with `{"source": "...", "group": "..."}`). The
sources are:

| `source` | Group comes from |
| --- | --- |
| `ldap` | the user's LDAP groups (when LDAP is enabled) |
| `oidc` | the instance provider's `groups_claim` |
| `org-oidc` | this organization's provider's `groups_claim` |

On each sign-in through that source, the user is added to or removed from the team to match
their groups. Group names compare case-insensitively. A synced team's members can't be edited
by hand. To manage the team by hand again, `DELETE` the sync; current members stay.

## Robot credentials

A robot's credential is shown once, when it is created or rotated. It can expire: pick
**Expires** when creating the robot (or send `expires_in_days`, `0` for never). Without a
choice, `policy.robot_expiry_days` applies, and if that is unset, credentials don't expire.
**Rotate** issues a new credential that lasts as long as the old one did, and the old one stops
working at once.

Robot owners, and org admins for org robots, can **Disable** a robot without deleting it. Its
credential and keyless sign-in stop working until it is enabled again. The API is
`PATCH /api/v1/auth/robots/{id}` or `PATCH /api/v1/orgs/{org}/robots/{id}`, with
`{"is_disabled": true}` or `{"description": "..."}`. Robot lists show when each credential
expires and when it was last used.

## Keyless robot logins

GitHub Actions, GitLab CI and other platforms give each job a short-lived OIDC token that
says which repository, branch and workflow it is. A robot can trust those tokens instead of
having a password (**Robot → Keyless**, or `PUT /api/v1/robots/{id}/federation`):

```json
{ "rules": [
  { "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:acme/api:ref:refs/heads/main",
    "audience": "kontainer" }
] }
```

- **`issuer`:** must be `https://`. Kontainer fetches its discovery document and signing keys,
  caches them, and refetches when keys rotate.
- **`subject`:** a pattern for the token's `sub`. `*` matches within a `/`-separated segment
  and `**` matches across segments, so use `repo:acme/api:ref:refs/heads/**` for every branch.
  A subject made only of `*` is refused, because it would trust every repository on GitHub.
- **`audience`:** set it, and request the same audience in CI. Without it the `aud` claim
  isn't checked, so a token minted for some other service would also work.

A robot can have up to 20 rules. In CI, the token is the password:

```yaml
# GitHub Actions
permissions:
  id-token: write
  contents: read
steps:
  - run: |
      TOKEN=$(curl -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
        "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=kontainer" | jq -r .value)
      echo "$TOKEN" | docker login registry.example.com -u acme+ci --password-stdin
```

```yaml
# GitLab CI
push:
  id_tokens:
    REGISTRY_ID_TOKEN:
      aud: kontainer
  script:
    - echo "$REGISTRY_ID_TOKEN" | docker login registry.example.com -u acme+ci --password-stdin
```

Tools that can't send a JWT as a password can exchange it for a one-hour robot access token:

```sh
curl -u "acme+ci:$TOKEN" https://registry.example.com/api/v1/auth/federation/token
# {"token": "kontainer_...", "username": "acme+ci", "expires_in": 3600, ...}
```

`/oauth2/federation/robot/token` is the same endpoint at a path other clients expect. The server logs every
federated sign-in and every refusal with the issuer and subject. Refusals also tell the client why,
for example `subject repo:acme/api:ref:refs/heads/dev does not match ...`.
