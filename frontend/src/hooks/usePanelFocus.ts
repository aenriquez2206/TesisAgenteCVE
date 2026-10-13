import { useEffect, useRef } from 'react'

export function usePanelFocus(open: boolean, close: () => void) {
  const ref = useRef<HTMLElement | null>(null)
  const closeRef = useRef(close)
  closeRef.current = close
  useEffect(() => {
    if (!open || !ref.current) return
    const previous = document.activeElement as HTMLElement | null
    const panel = ref.current
    const focusable = () => [...panel.querySelectorAll<HTMLElement>('button:not(:disabled), a[href], textarea, [tabindex="0"]')]
      .filter(el => el.getClientRects().length > 0)
    focusable()[0]?.focus()
    function keydown(event: KeyboardEvent) {
      if (event.key === 'Escape') { event.preventDefault(); closeRef.current() }
      if (event.key !== 'Tab') return
      const nodes = focusable()
      const first = nodes[0], last = nodes[nodes.length - 1]
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus() }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus() }
    }
    panel.addEventListener('keydown', keydown)
    return () => { panel.removeEventListener('keydown', keydown); previous?.focus() }
  }, [open])
  return ref
}
