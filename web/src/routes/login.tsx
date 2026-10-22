import { Link, useSearchParams } from "react-router"
import { ContainerIcon } from "lucide-react"
import { LoginForm } from "@/components/login-form"

export function LoginPage() {
  const [params] = useSearchParams()
  return (
    <div className="bg-background flex min-h-svh flex-col items-center justify-center gap-6 p-6 md:p-10">
      <div className="flex w-full max-w-sm flex-col gap-6">
        <a href="/" className="flex items-center gap-2 self-center font-medium">
          <div className="bg-primary text-primary-foreground flex size-6 items-center justify-center rounded-sm">
            <ContainerIcon className="size-4" />
          </div>
          Kontainer
        </a>
        <LoginForm redirect={params.get("redirect") ?? "/"} initialError={params.get("error")} />
        <Link to="/explore" className="text-center text-sm text-muted-foreground hover:underline">Browse public images without signing in</Link>
      </div>
    </div>
  )
}
