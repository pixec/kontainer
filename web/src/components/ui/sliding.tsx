import * as React from "react"
import { cn } from "cn"

// Shared by tab bars and side navs: items are marked `data-tab-item`, the active one
// `aria-current="page"` (links) or `data-state="active"` (in-page tabs). The bar must be
// `position: relative`.

const ACTIVE = '[data-tab-item][aria-current="page"], [data-tab-item][data-state="active"]'

/** Measure the active item of `bar` now and whenever items change or resize. */
function useActiveBox(bar: React.RefObject<HTMLElement | null>) {
  const [box, setBox] = React.useState<{ left: number; top: number; width: number; height: number; slide: boolean } | null>(null)
  const placed = React.useRef(false)
  // A passive effect, not a layout one: layout effects run before the parent bar's ref is
  // attached, so `bar.current` would still be null on mount and nothing would ever be measured.
  React.useEffect(() => {
    const el = bar.current
    if (!el) return
    const measure = () => {
      const a = el.querySelector<HTMLElement>(ACTIVE)
      if (!a) {
        placed.current = false
        setBox(null)
        return
      }
      const next = { left: a.offsetLeft, top: a.offsetTop, width: a.offsetWidth, height: a.offsetHeight }
      setBox((prev) => (prev && prev.left === next.left && prev.top === next.top && prev.width === next.width && prev.height === next.height ? prev : { ...next, slide: placed.current }))
      placed.current = true
    }
    // Items change size without the bar doing so (the web font arriving, a count appearing), so
    // watch every item, and re-watch when items come and go.
    const size = new ResizeObserver(measure)
    const watch = () => {
      size.disconnect()
      size.observe(el)
      el.querySelectorAll("[data-tab-item]").forEach((item) => size.observe(item))
    }
    watch()
    measure()
    const attrs = new MutationObserver((records) => {
      if (records.some((r) => r.type === "childList")) watch()
      measure()
    })
    attrs.observe(el, { subtree: true, childList: true, attributes: true, attributeFilter: ["aria-current", "data-state"] })
    let alive = true
    document.fonts?.ready.then(() => { if (alive) measure() })
    return () => {
      alive = false
      attrs.disconnect()
      size.disconnect()
    }
  }, [bar])
  return box
}

/**
 * One hover background per bar (tabs or a side nav) that slides to the item under the pointer,
 * instead of each item lighting up on its own. It appears in place when the pointer enters the bar (no slide in
 * from the edge) and fades out when it leaves.
 */
export function HoverPill({ bar }: { bar: React.RefObject<HTMLElement | null> }) {
  const [pill, setPill] = React.useState<{ left: number; top: number; width: number; height: number; slide: boolean } | null>(null)
  const [shown, setShown] = React.useState(false)
  const shownRef = React.useRef(false)
  React.useEffect(() => {
    const el = bar.current
    if (!el) return
    const over = (e: PointerEvent) => {
      const item = (e.target as HTMLElement).closest<HTMLElement>("[data-tab-item]")
      if (!item || !el.contains(item) || item.matches(":disabled")) return
      setPill({ left: item.offsetLeft, top: item.offsetTop, width: item.offsetWidth, height: item.offsetHeight, slide: shownRef.current })
      shownRef.current = true
      setShown(true)
    }
    const leave = () => {
      shownRef.current = false
      setShown(false)
    }
    el.addEventListener("pointerover", over)
    el.addEventListener("pointerleave", leave)
    return () => {
      el.removeEventListener("pointerover", over)
      el.removeEventListener("pointerleave", leave)
    }
  }, [bar])
  if (!pill) return null
  return (
    <span aria-hidden className={cn(
      "pointer-events-none absolute rounded-md bg-accent motion-reduce:transition-none",
      pill.slide ? "transition-[left,top,width,height,opacity] duration-200 ease-out" : "transition-opacity duration-150",
      shown ? "opacity-100" : "opacity-0",
    )} style={{ left: pill.left, top: pill.top, width: pill.width, height: pill.height }} />
  )
}

/** The active tab's underline, drawn once per bar so it slides from tab to tab. No slide on first paint. */
export function ActiveUnderline({ bar }: { bar: React.RefObject<HTMLElement | null> }) {
  const box = useActiveBox(bar)
  if (!box) return null
  return (
    <span aria-hidden className={cn("pointer-events-none absolute bottom-0 h-0.5 rounded-full bg-foreground motion-reduce:transition-none", box.slide && "transition-[left,width] duration-300 ease-out")}
      style={{ left: box.left, width: box.width }} />
  )
}

/** The active side-nav item's left marker, sliding up and down between items. */
export function ActiveBox({ bar }: { bar: React.RefObject<HTMLElement | null> }) {
  const box = useActiveBox(bar)
  if (!box) return null
  const slide = box.slide && "transition-[top,height] duration-300 ease-out"
  return <span aria-hidden className={cn("pointer-events-none absolute w-0.5 rounded-full bg-foreground motion-reduce:transition-none", slide)} style={{ left: box.left - 10, top: box.top + 8, height: box.height - 16 }} />
}
