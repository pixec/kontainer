// Every date and duration shown in the UI goes through here (date-fns).
import { addDays, differenceInSeconds, format, formatDistanceToNowStrict, formatDuration, intervalToDuration, isValid, parseISO, subDays, type Duration } from "date-fns"

type DateLike = string | Date | null | undefined

function toDate(d: DateLike): Date | null {
  if (!d) return null
  const v = typeof d === "string" ? parseISO(d) : d
  return isValid(v) ? v : null
}

/** "3 hours ago", or "in 2 days" for future times. */
export function relativeTime(d: DateLike): string {
  const v = toDate(d)
  return v ? formatDistanceToNowStrict(v, { addSuffix: true }) : ""
}

/** "Oct 14, 2026, 3:04 PM" in the viewer's locale and time zone. */
export function formatDate(d: DateLike): string {
  const v = toDate(d)
  return v ? format(v, "PPp") : ""
}

/** For `<input type="datetime-local">`. */
export const toLocalInput = (d: Date) => format(d, "yyyy-MM-dd'T'HH:mm")

/** ISO timestamp `days` from now (negative: in the past). */
export const daysFromNow = (days: number) => (days >= 0 ? addDays(new Date(), days) : subDays(new Date(), -days)).toISOString()

/** Whether `d` is less than `secs` away. */
export const within = (d: DateLike, secs: number) => {
  const v = toDate(d)
  return !!v && differenceInSeconds(v, new Date()) < secs
}

/** Seconds as the largest one or two units: "7 days", "1 hour 30 minutes", "45 seconds". */
export function formatSeconds(secs: number, units = 2): string {
  if (secs <= 0) return "0 seconds"
  const d = intervalToDuration({ start: 0, end: secs * 1000 })
  const order: (keyof Duration)[] = ["years", "months", "days", "hours", "minutes", "seconds"]
  const first = order.findIndex((k) => d[k])
  return formatDuration(d, { format: order.slice(first, first + units), zero: false })
}

/** Compact elapsed time between two moments (default: until now): "42s", "3m 5s", "2h 10m". */
export function elapsed(start: DateLike, end?: DateLike): string {
  const a = toDate(start)
  if (!a) return ""
  const s = Math.max(0, differenceInSeconds(toDate(end) ?? new Date(), a))
  const d = intervalToDuration({ start: 0, end: s * 1000 })
  const days = (d.years ?? 0) * 365 + (d.months ?? 0) * 30 + (d.days ?? 0)
  if (days) return `${days}d ${d.hours ?? 0}h`
  if (d.hours) return `${d.hours}h ${d.minutes ?? 0}m`
  if (d.minutes) return `${d.minutes}m ${d.seconds ?? 0}s`
  return `${d.seconds ?? 0}s`
}
