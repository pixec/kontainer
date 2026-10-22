import { useMutation, useQueryClient } from "@tanstack/react-query"
import { StarIcon } from "lucide-react"
import { endpoints, type StarState } from "@/lib/api"
import { useSession } from "@/lib/session"
import { cn } from "@/lib/utils"

function useStar(name: string) {
  const qc = useQueryClient()
  return useMutation({
    meta: { error: "Couldn't update your star" },
    mutationFn: (starred: boolean) => endpoints.setStar(name, starred),
    onSuccess: () => {
      for (const key of [["repo-meta", name], ["repositories"], ["stars"], ["explore"]]) qc.invalidateQueries({ queryKey: key })
    },
  })
}

/** Star toggle with count, GitHub style. Anonymous visitors only see the count. */
export function StarButton({ name, state }: { name: string; state: StarState }) {
  const { me } = useSession()
  const star = useStar(name)
  // Show the intended state while the request is in flight.
  const starred = star.isPending ? star.variables : state.is_starred
  const count = state.stars + (star.isPending ? (star.variables ? 1 : -1) : 0)
  const signedIn = !!me?.username
  return (
    <div className="inline-flex h-9 items-stretch overflow-hidden rounded-lg border bg-card text-sm">
      <button type="button" disabled={!signedIn || star.isPending} onClick={() => star.mutate(!starred)} title={signedIn ? undefined : "Sign in to star"}
        className="flex items-center gap-2 px-3 font-medium transition-colors hover:bg-accent disabled:cursor-default disabled:hover:bg-transparent">
        <StarIcon className={cn("size-4", starred ? "fill-warning text-warning" : "text-muted-foreground")} />
        {starred ? "Starred" : "Star"}
      </button>
      <span className="flex min-w-9 items-center justify-center border-l px-2.5 tabular-nums text-muted-foreground">{count}</span>
    </div>
  )
}

/** Compact icon toggle for table rows. */
export function StarToggle({ name, state }: { name: string; state: StarState }) {
  const { me } = useSession()
  const star = useStar(name)
  const starred = star.isPending ? star.variables : state.is_starred
  const count = state.stars + (star.isPending ? (star.variables ? 1 : -1) : 0)
  return (
    <button type="button" disabled={!me?.username || star.isPending} onClick={(e) => { e.stopPropagation(); star.mutate(!starred) }}
      title={starred ? "Unstar" : "Star"}
      className="inline-flex items-center gap-1.5 rounded-md px-1.5 py-1 text-sm tabular-nums text-muted-foreground transition-colors hover:bg-accent hover:text-foreground disabled:hover:bg-transparent">
      <StarIcon className={cn("size-4", starred && "fill-warning text-warning")} />
      {count}
    </button>
  )
}
