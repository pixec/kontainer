/**
 * The last copy of a few small, slow-changing answers (who is signed in, their organizations),
 * kept in localStorage so a refresh renders the real UI at once while they are fetched again.
 * Cleared on sign-in and sign-out.
 */
const PREFIX = "kontainer-cache:"

export function cached<T>(key: string): T | undefined {
  try {
    const raw = localStorage.getItem(PREFIX + key)
    return raw ? (JSON.parse(raw) as T) : undefined
  } catch {
    return undefined
  }
}

export function remember<T>(key: string, value: T): T {
  try { localStorage.setItem(PREFIX + key, JSON.stringify(value)) } catch { /* full or blocked */ }
  return value
}

export function forgetCached() {
  try {
    for (const k of Object.keys(localStorage)) if (k.startsWith(PREFIX)) localStorage.removeItem(k)
  } catch { /* blocked */ }
}
