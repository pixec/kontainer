import { HourglassIcon } from "lucide-react"
import { LabeledSelect } from "@/components/page"
import type { Robot } from "@/lib/api"
import { formatDate, relativeTime, within } from "@/lib/time"
import { cn } from "@/lib/utils"

/** Disabled, expired, or expiring: what keeps a robot's credential from working (soon). */
export function RobotStatus({ robot }: { robot: Robot }) {
  if (robot.is_disabled) return <span className="chip">Disabled</span>
  if (!robot.expires_at) return null
  // Within 0 seconds from now: already in the past.
  const expired = within(robot.expires_at, 0)
  const soon = within(robot.expires_at, 7 * 86400)
  return (
    <span className={cn("chip", expired ? "bg-destructive/15 text-destructive" : soon && "bg-warning/15 text-warning")} title={formatDate(robot.expires_at)}>
      <HourglassIcon className="size-3" />{expired ? "Expired" : `Expires ${relativeTime(robot.expires_at)}`}
    </span>
  )
}

const EXPIRY: [string, string][] = [["", "Registry default"], ["30", "30 days"], ["90", "90 days"], ["365", "1 year"], ["0", "Never"]]

/** How long a new robot credential lasts; `undefined` leaves it to the registry's default. */
export function ExpirySelect({ value, onChange }: { value: number | undefined; onChange: (days: number | undefined) => void }) {
  return <LabeledSelect label="Expires" value={value === undefined ? "" : String(value)} onChange={(v) => onChange(v === "" ? undefined : Number(v))} options={EXPIRY} className="w-full" />
}
