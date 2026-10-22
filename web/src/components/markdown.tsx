import DOMPurify from "dompurify"
import { marked } from "marked"
import { useMemo } from "react"

export function Markdown({ source }: { source: string }) {
  const html = useMemo(() => DOMPurify.sanitize(marked.parse(source, { async: false }) as string), [source])
  if (!source.trim()) return null
  return (
    <div
      className="prose prose-sm dark:prose-invert max-w-none [&_pre]:bg-muted [&_pre]:p-3 [&_pre]:rounded-md [&_pre]:overflow-auto [&_code]:text-xs [&_h1]:text-lg [&_h2]:text-base [&_h3]:text-sm [&_h1,&_h2,&_h3]:font-semibold [&_h1,&_h2,&_h3]:mt-4 [&_h1,&_h2,&_h3]:mb-2 [&_p]:my-2 [&_ul]:list-disc [&_ul]:pl-5 [&_ol]:list-decimal [&_ol]:pl-5 [&_a]:underline [&_table]:text-sm [&_td,&_th]:border [&_td,&_th]:px-2 [&_td,&_th]:py-1"
      dangerouslySetInnerHTML={{ __html: html }}
    />
  )
}
