// Passkeys in the browser: the server's WebAuthn options are JSON with base64url strings where
// `navigator.credentials` wants ArrayBuffers, and the credential it returns goes back as JSON
// the same way.

import { endpoints } from "@/lib/api"

export const passkeysSupported = () => typeof window !== "undefined" && !!window.PublicKeyCredential && !!navigator.credentials

function fromB64url(s: string): ArrayBuffer {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out.buffer
}

function toB64url(buf: ArrayBuffer | null | undefined): string | null {
  if (!buf) return null
  const bytes = new Uint8Array(buf)
  let bin = ""
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

type Json = Record<string, unknown>
type Descriptor = { id: string; type: string; transports?: string[] }

function descriptors(list: unknown): PublicKeyCredentialDescriptor[] | undefined {
  if (!Array.isArray(list)) return undefined
  return (list as Descriptor[]).map((c) => ({ ...c, type: "public-key", id: fromB64url(c.id), transports: c.transports as AuthenticatorTransport[] | undefined }))
}

function creationOptions(o: Json): PublicKeyCredentialCreationOptions {
  const user = o.user as Json
  return {
    ...(o as unknown as PublicKeyCredentialCreationOptions),
    challenge: fromB64url(o.challenge as string),
    user: { ...(user as unknown as PublicKeyCredentialUserEntity), id: fromB64url(user.id as string) },
    excludeCredentials: descriptors(o.excludeCredentials),
  }
}

function requestOptions(o: Json): PublicKeyCredentialRequestOptions {
  const allow = descriptors(o.allowCredentials)
  return { ...(o as unknown as PublicKeyCredentialRequestOptions), challenge: fromB64url(o.challenge as string), allowCredentials: allow && allow.length > 0 ? allow : undefined }
}

/** Create a passkey named `name` on this device and register it with the account. */
export async function registerPasskey(name: string) {
  const { challenge_id, options } = await endpoints.passkeyRegisterStart(name)
  const cred = (await navigator.credentials.create({ publicKey: creationOptions(options.publicKey) })) as PublicKeyCredential | null
  if (!cred) throw new Error("No passkey was created.")
  const r = cred.response as AuthenticatorAttestationResponse
  return endpoints.passkeyRegisterFinish(challenge_id, {
    id: cred.id,
    rawId: toB64url(cred.rawId),
    type: cred.type,
    response: { attestationObject: toB64url(r.attestationObject), clientDataJSON: toB64url(r.clientDataJSON), transports: r.getTransports?.() ?? undefined },
    extensions: cred.getClientExtensionResults?.() ?? {},
  })
}

/** Sign in with a passkey; without `username`, the authenticator offers its discoverable ones. */
export async function signInWithPasskey(username?: string) {
  const { challenge_id, options } = await endpoints.passkeyLoginStart(username)
  const cred = (await navigator.credentials.get({ publicKey: requestOptions(options.publicKey) })) as PublicKeyCredential | null
  if (!cred) throw new Error("No passkey was chosen.")
  const r = cred.response as AuthenticatorAssertionResponse
  return endpoints.passkeyLoginFinish(challenge_id, {
    id: cred.id,
    rawId: toB64url(cred.rawId),
    type: cred.type,
    response: { authenticatorData: toB64url(r.authenticatorData), clientDataJSON: toB64url(r.clientDataJSON), signature: toB64url(r.signature), userHandle: toB64url(r.userHandle) },
    extensions: cred.getClientExtensionResults?.() ?? {},
  })
}
