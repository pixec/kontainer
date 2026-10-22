import { useForm } from "@tanstack/react-form"
import { useState } from "react"
import { useNavigate } from "react-router"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldSeparator } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { cn } from "@/lib/utils"
import { useSession } from "@/lib/session"
import { passkeysSupported } from "@/lib/webauthn"
import { KeyRoundIcon } from "lucide-react"

export function LoginForm({ className, redirect = "/", initialError, ...props }: React.ComponentProps<"div"> & { redirect?: string; initialError?: string | null }) {
  const { login, loginWithPasskey, me } = useSession()
  const [passkeyBusy, setPasskeyBusy] = useState(false)
  const navigate = useNavigate()
  const [error, setError] = useState<string | null>(initialError ?? null)
  const [step, setStep] = useState<"password" | "mfa">("password")
  const [useRecovery, setUseRecovery] = useState(false)

  const form = useForm({
    defaultValues: { username: "", password: "", otp: "", recovery: "" },
    onSubmit: async ({ value }) => {
      setError(null)
      try {
        const result = await login(
          value.username,
          value.password,
          step === "mfa" && !useRecovery ? value.otp : undefined,
          step === "mfa" && useRecovery ? value.recovery : undefined,
        )
        if (result === "mfa") { setStep("mfa"); return }
        navigate(redirect)
      } catch (e) {
        setError(e instanceof Error ? e.message : "Sign-in failed")
      }
    },
  })

  // With a username typed, that account's passkeys are offered; without, any passkey this device has.
  const passkey = async () => {
    setError(null)
    setPasskeyBusy(true)
    try {
      await loginWithPasskey(form.getFieldValue("username").trim() || undefined)
      navigate(redirect)
    } catch (e) {
      // The user closing the browser's dialog is not an error worth showing.
      if (!(e instanceof DOMException && e.name === "NotAllowedError")) setError(e instanceof Error ? e.message : "Passkey sign-in failed")
    } finally {
      setPasskeyBusy(false)
    }
  }

  const text = (name: "username" | "password" | "otp" | "recovery", label: string, input: React.ComponentProps<typeof Input>) => (
    <form.Field
      name={name}
      validators={{ onChange: ({ value }) => (value.trim() ? undefined : `${label} is required`) }}
      children={(f) => {
        const invalid = f.state.meta.isTouched && f.state.meta.errors.length > 0
        return (
          <Field data-invalid={invalid || undefined}>
            <FieldLabel htmlFor={f.name}>{label}</FieldLabel>
            <Input id={f.name} name={f.name} value={f.state.value} onBlur={f.handleBlur} onChange={(e) => f.handleChange(e.target.value)} aria-invalid={invalid} {...input} />
            {invalid && <FieldError>{String(f.state.meta.errors[0])}</FieldError>}
          </Field>
        )
      }}
    />
  )

  return (
    <div className={cn("flex flex-col gap-6", className)} {...props}>
      <Card>
        <CardHeader className="text-center">
          <CardTitle className="text-xl">{step === "mfa" ? "Two-factor authentication" : "Welcome back"}</CardTitle>
          <CardDescription>
            {step === "mfa"
              ? useRecovery ? "Enter one of your recovery codes." : "Enter the 6-digit code from your authenticator app."
              : me?.oidc ? `Sign in with ${me.oidc} or your registry account` : "Sign in with your registry account"}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={(e) => { e.preventDefault(); e.stopPropagation(); form.handleSubmit() }}>
            <FieldGroup>
              {step === "password" && me?.oidc && (
                <>
                  <Field>
                    <Button variant="outline" type="button" asChild>
                      <a href={`/auth/oidc/login?redirect=${encodeURIComponent(redirect)}`}>Continue with {me.oidc}</a>
                    </Button>
                  </Field>
                  <FieldSeparator className="*:data-[slot=field-separator-content]:bg-card">Or continue with</FieldSeparator>
                </>
              )}
              {step === "password" && text("username", "Username", { autoComplete: "username", autoFocus: true })}
              {step === "password" && text("password", "Password", { type: "password", autoComplete: "current-password" })}
              {step === "mfa" && !useRecovery && text("otp", "One-time code", { inputMode: "numeric", autoComplete: "one-time-code", autoFocus: true, placeholder: "123456" })}
              {step === "mfa" && useRecovery && text("recovery", "Recovery code", { autoFocus: true, placeholder: "xxxxx-xxxxx" })}
              {error && <FieldError>{error}</FieldError>}
              <Field>
                <form.Subscribe
                  selector={(s) => s.isSubmitting}
                  children={(busy) => <Button type="submit" disabled={busy}>{busy ? "Signing in..." : step === "mfa" ? "Verify" : "Sign in"}</Button>}
                />
                {step === "password" && me?.passkeys && passkeysSupported() && (
                  <Button type="button" variant="outline" disabled={passkeyBusy} onClick={passkey}><KeyRoundIcon />{passkeyBusy ? "Waiting for your passkey..." : "Sign in with a passkey"}</Button>
                )}
                {step === "password" && <OrgSsoLink redirect={redirect} />}
                {step === "mfa" && (
                  <FieldDescription className="text-center">
                    <button type="button" className="underline underline-offset-4" onClick={() => setUseRecovery(!useRecovery)}>
                      {useRecovery ? "Use authenticator code instead" : "Use a recovery code instead"}
                    </button>
                  </FieldDescription>
                )}
              </Field>
            </FieldGroup>
          </form>
        </CardContent>
      </Card>
      <FieldDescription className="px-6 text-center">
        Command-line tools sign in with <code>docker login {location.host}</code> using a personal access token.
      </FieldDescription>
    </div>
  )
}

/** "Sign in with your organization's SSO": asks for the organization, then goes to its provider. */
function OrgSsoLink({ redirect }: { redirect: string }) {
  const [open, setOpen] = useState(false)
  const [org, setOrg] = useState("")
  const go = () => { if (org.trim()) location.href = `/auth/oidc/orgs/${encodeURIComponent(org.trim().toLowerCase())}/login?redirect=${encodeURIComponent(redirect)}` }
  if (!open) {
    return (
      <FieldDescription className="text-center">
        <button type="button" className="underline underline-offset-4" onClick={() => setOpen(true)}>Sign in with your organization's SSO</button>
      </FieldDescription>
    )
  }
  return (
    <div className="flex gap-2">
      <Input autoFocus placeholder="Organization, e.g. acme" value={org} onChange={(e) => setOrg(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); go() } }} />
      <Button type="button" variant="outline" disabled={!org.trim()} onClick={go}>Continue</Button>
    </div>
  )
}
