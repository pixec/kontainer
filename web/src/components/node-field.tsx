import { useEffect, useRef } from "react"

type Node = { x: number; y: number; vx: number; vy: number; size: number; shade: number }

/** Drifting squares joined by faint lines when close; a quiet backdrop for the Explore hero.
 *  Monochrome to match the theme. Static when the viewer prefers reduced motion. */
export function NodeField({ className }: { className?: string }) {
  const ref = useRef<HTMLCanvasElement>(null)
  useEffect(() => {
    const canvas = ref.current
    const ctx = canvas?.getContext("2d")
    if (!canvas || !ctx) return
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches
    let w = 0, h = 0, raf = 0
    let nodes: Node[] = []
    const seed = () => {
      const count = Math.round(Math.min(48, Math.max(18, (w * h) / 26000)))
      nodes = Array.from({ length: count }, () => ({
        x: Math.random() * w, y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.12, vy: (Math.random() - 0.5) * 0.12,
        // Mostly tiny specks, a few larger blocks.
        size: Math.random() < 0.2 ? 10 + Math.random() * 12 : 2 + Math.random() * 5,
        shade: 40 + Math.random() * 180,
      }))
    }
    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2)
      w = canvas.clientWidth; h = canvas.clientHeight
      canvas.width = w * dpr; canvas.height = h * dpr
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      seed()
    }
    const LINK = 150
    const draw = () => {
      ctx.clearRect(0, 0, w, h)
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i], b = nodes[j]
          const d = Math.hypot(a.x - b.x, a.y - b.y)
          if (d < LINK) {
            ctx.strokeStyle = `rgba(255,255,255,${0.09 * (1 - d / LINK)})`
            ctx.lineWidth = 1
            ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke()
          }
        }
      }
      for (const n of nodes) {
        const s = Math.round(n.shade)
        ctx.fillStyle = `rgba(${s},${s},${s},${n.size > 9 ? 0.55 : 0.8})`
        ctx.fillRect(n.x - n.size / 2, n.y - n.size / 2, n.size, n.size)
      }
    }
    const step = () => {
      for (const n of nodes) {
        n.x += n.vx; n.y += n.vy
        if (n.x < -20) n.x = w + 20; if (n.x > w + 20) n.x = -20
        if (n.y < -20) n.y = h + 20; if (n.y > h + 20) n.y = -20
      }
      draw()
      raf = requestAnimationFrame(step)
    }
    resize()
    if (reduce) draw(); else raf = requestAnimationFrame(step)
    const ro = new ResizeObserver(() => { resize(); if (reduce) draw() })
    ro.observe(canvas)
    return () => { cancelAnimationFrame(raf); ro.disconnect() }
  }, [])
  return <canvas ref={ref} aria-hidden className={className} />
}
