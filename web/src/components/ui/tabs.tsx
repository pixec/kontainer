"use client"

import * as React from "react"
import { cn } from "cn"
import { Tabs as TabsPrimitive } from "radix-ui"
import { Link, useLocation } from "react-router"
import { ActiveUnderline, HoverPill } from "@/components/ui/sliding"

/**
 * One tab style for every horizontal tab bar: in-page tabs (`TabsTrigger`, active via
 * `data-state`) and route tabs (`TabNavLink`, active via `aria-current`). Same weight in every
 * state so switching never shifts layout; the active underline sits on the bar's divider.
 */
export const tabItemClass = cn(
  "relative mb-2 inline-flex h-8 shrink-0 items-center justify-center gap-2 rounded-md px-3 text-sm font-medium whitespace-nowrap text-muted-foreground outline-none transition-colors",
  // The hover background is the bar's sliding pill (`HoverPill`); keyboard focus keeps its own.
  "hover:text-foreground focus-visible:bg-accent focus-visible:text-foreground disabled:pointer-events-none disabled:opacity-50",
  "data-[state=active]:text-foreground aria-[current=page]:text-foreground",
  "[&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
)

/**
 * The bar: tabs left-aligned on a full-width divider, scrolling sideways when narrow. The
 * divider is an inset shadow (painted inside the bar) so the active underline can sit on it
 * without overflowing, which would otherwise make the bar scroll vertically.
 */
export const tabBarClass = "relative flex w-full items-center justify-start gap-1 overflow-x-auto overflow-y-hidden text-muted-foreground shadow-[inset_0_-1px_0_var(--border)]"

function Tabs({ className, orientation = "horizontal", ...props }: React.ComponentProps<typeof TabsPrimitive.Root>) {
  return (
    <TabsPrimitive.Root data-slot="tabs" data-orientation={orientation} className={cn("group/tabs flex gap-2 data-horizontal:flex-col", className)} {...props} />
  )
}

function TabsList({ className, children, ...props }: React.ComponentProps<typeof TabsPrimitive.List>) {
  const bar = React.useRef<HTMLDivElement>(null)
  return (
    // Pills hang 12px into the margin so the first icon sits on the content edge, like the navbar.
    <TabsPrimitive.List ref={bar} data-slot="tabs-list" className={cn(tabBarClass, "-mx-3 w-auto", className)} {...props}>
      <HoverPill bar={bar} />
      {children}
      <ActiveUnderline bar={bar} />
    </TabsPrimitive.List>
  )
}

function TabsTrigger({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.Trigger>) {
  return <TabsPrimitive.Trigger data-slot="tabs-trigger" data-tab-item="" className={cn(tabItemClass, className)} {...props} />
}

function TabsContent({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.Content>) {
  return <TabsPrimitive.Content data-slot="tabs-content" className={cn("flex-1 text-sm outline-none", className)} {...props} />
}

/** A bar of route tabs (links), styled like `TabsList`. */
function TabNav({ className, children, ...props }: React.ComponentProps<"nav">) {
  const bar = React.useRef<HTMLElement>(null)
  return (
    <nav ref={bar} data-slot="tab-nav" className={cn(tabBarClass, className)} {...props}>
      <HoverPill bar={bar} />
      {children}
      <ActiveUnderline bar={bar} />
    </nav>
  )
}

/** A tab that navigates. Active when the location matches `to` (or starts with `match`), or starts with any of `also`. */
function TabNavLink({ to, exact, match, also, className, ...props }: React.ComponentProps<typeof Link> & { to: string; exact?: boolean; match?: string; also?: string[] }) {
  const { pathname } = useLocation()
  const active = (match ? pathname.startsWith(match) : exact ? pathname === to : pathname.startsWith(to)) || !!also?.some((p) => pathname.startsWith(p))
  return <Link to={to} aria-current={active ? "page" : undefined} data-tab-item="" className={cn(tabItemClass, className)} {...props} />
}

/** Small count shown after a tab label. */
function TabCount({ children, className }: { children: React.ReactNode; className?: string }) {
  return <span className={cn("ml-0.5 inline-flex h-4.5 min-w-4.5 items-center justify-center rounded-md bg-foreground/10 px-1.5 text-[11px] font-medium tabular-nums text-foreground", className)}>{children}</span>
}

export { Tabs, TabsList, TabsTrigger, TabsContent, TabNav, TabNavLink, TabCount }
