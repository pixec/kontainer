import type { Rule } from "@/lib/api"

/** Human summary of a legacy scoped token's rules (scopes can no longer be created). */
export function describeRules(rules: Rule[] | null): string {
  if (!rules) return "full access"
  return rules
    .map((r) => {
      const level = r.actions.includes("delete") || r.actions.includes("admin") ? "read, write & delete" : r.actions.includes("push") ? "read & write" : "read-only"
      const where = r.repositories.map((p) => (p === "**" ? "all repositories" : p.endsWith("/**") ? `everything in ${p.slice(0, -3)}` : p)).join(", ")
      return `${level} on ${where}`
    })
    .join("; ")
}
