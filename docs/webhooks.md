# Webhooks

Kontainer can send an HTTP `POST` to your endpoint when something happens: an image is pushed,
a scan finishes, a build fails, a namespace nears its quota.

There are two kinds:

- **Namespace webhooks**, managed in the UI by a namespace's admins: **Settings → Webhooks**
  for your own namespace, or the organization's **Settings → Webhooks**. They keep a delivery
  history.
- **Config webhooks** (`[[webhooks]]` in the config file), for the whole registry. They have no
  history and no UI.

## Events

| Event | When |
| --- | --- |
| `push` | A manifest is pushed (tag or digest) |
| `pull` | A manifest is pulled (not `HEAD`) |
| `delete` | A tag or manifest is deleted |
| `scan` | A vulnerability scan finishes or fails (`scan.status`) |
| `quota_exceeded` | A push is refused because it would exceed the namespace's quota |
| `quota_warning` | A push takes the namespace past 90% of its quota |
| `retention` | A retention policy deleted tags (`details.deleted`) |
| `mirror_sync` | A mirror finished syncing (`details.ok`, `details.message`) |
| `build` | A build from Git ended (`details.status`: succeeded, failed or cancelled) |
| `replication` | A replication to another registry finished |
| `ping` | **Test** in the UI |

A namespace webhook with no events selected gets every event, including ones added later.
Repository filters are globs relative to the namespace (`api`, `web/*`). They don't apply to
namespace-wide events such as `retention`.

Config webhooks with no `events` get `push`, `delete` and `scan`, as they always have. List
other events explicitly.

## Formats

**Kontainer JSON** (default):

```json
{
  "type": "push",
  "timestamp": "2026-10-14T09:48:53.941Z",
  "repository": "acme/api",
  "tag": "v1.2.0",
  "digest": "sha256:...",
  "media_type": "application/vnd.oci.image.manifest.v1+json",
  "actor": "alice"
}
```

**CloudEvents 1.0** (structured mode, `content-type: application/cloudevents+json`): `type` is
`dev.kontainer.<event>`, `source` is the repository's URL, `subject` the tag or digest, and
`data` the Kontainer JSON above.

**Slack**: `{"text": "..."}` with a one-line summary, for Slack incoming webhooks and compatible
chat tools.

## Headers and signatures

Every request carries `X-Kontainer-Event` (the event) and `X-Kontainer-Delivery` (the delivery
id). With a **signing secret**, `X-Kontainer-Signature: sha256=<hex>` is the HMAC-SHA256 of the
raw body, like GitHub's. Check it before trusting a request:

```python
import hmac, hashlib
expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
assert hmac.compare_digest(expected, request.headers["X-Kontainer-Signature"])
```

An **Authorization header** is sent as written, e.g. `Bearer ...`. Neither the secret nor the
header is shown again after saving. Leave the field empty on an edit to keep it, unless the edit
moves the webhook to another origin (scheme, host or port): then the stored secret and header
are cleared, so a credential meant for one receiver never goes to another. Enter them again for
the new URL.

## Deliveries

A delivery succeeds on any `2xx` answer within 15 seconds. Otherwise it is tried twice more,
after 2 and 4 seconds. Redirects are not followed.

The last 50 deliveries of each webhook are kept, with the request body, the response code, the
first KB of the response (reading stops there) and any error. **Redeliver** sends the same body again as a new
delivery.

## Internal addresses

Namespace webhooks refuse URLs that resolve to this machine, private networks
(`10/8`, `172.16/12`, `192.168/16`, `fc00::/7`, ...), link-local addresses or cloud metadata
endpoints (`169.254.169.254`). Otherwise, anyone who can create a webhook could use the
registry to reach services only it can see. To allow internal targets, for example a chat
bridge inside your network:

```toml
[policy]
webhooks_allow_private_targets = true
```

Config webhooks are set by the operator and are not checked.
