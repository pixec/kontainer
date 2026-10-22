import { useEffect, useState } from "react"
import { CheckCircle2Icon, CircleAlertIcon, InfoIcon, Loader2Icon, TriangleAlertIcon } from "lucide-react"
import { Toaster as Sonner, type ToasterProps } from "sonner"

/** Follows the `dark` class on <html>, like the rest of the UI. */
function useTheme(): ToasterProps["theme"] {
  const read = (): "dark" | "light" => (document.documentElement.classList.contains("dark") ? "dark" : "light")
  const [theme, setTheme] = useState(read)
  useEffect(() => {
    const obs = new MutationObserver(() => setTheme(read()))
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] })
    return () => obs.disconnect()
  }, [])
  return theme
}

export function Toaster(props: ToasterProps) {
  return (
    <Sonner
      theme={useTheme()}
      className="toaster group"
      icons={{
        success: <CheckCircle2Icon className="size-4 text-emerald-500" />,
        error: <CircleAlertIcon className="size-4 text-destructive" />,
        info: <InfoIcon className="size-4" />,
        warning: <TriangleAlertIcon className="size-4 text-amber-500" />,
        loading: <Loader2Icon className="size-4 animate-spin" />,
      }}
      style={{
        "--normal-bg": "var(--popover)",
        "--normal-text": "var(--popover-foreground)",
        "--normal-border": "var(--border)",
        "--border-radius": "var(--radius)",
      } as React.CSSProperties}
      toastOptions={{ classNames: { description: "!text-muted-foreground" } }}
      {...props}
    />
  )
}
