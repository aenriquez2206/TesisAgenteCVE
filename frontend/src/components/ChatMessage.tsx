import { useState } from 'react'
import ReactMarkdown from 'react-markdown'
import type { Message } from '../types/api'

export function ChatMessage({ message, onRetry, onEvidence, selected, busy }: {
  message: Message; onRetry: (id: string) => void; onEvidence: (id: string) => void; selected: boolean; busy: boolean
}) {
  const [copyStatus, setCopyStatus] = useState('')
  async function copy() {
    try { await navigator.clipboard.writeText(message.content); setCopyStatus('Copiado') }
    catch { setCopyStatus('No se pudo copiar. Selecciona el texto de la respuesta.') }
  }
  if (message.role === 'user') return <div className="user-message">{message.content}</div>
  if (message.error) return <article className="answer error" role="alert"><strong>No se completó la consulta</strong><p>{message.error}</p><button disabled={busy} onClick={() => onRetry(message.id)}>Reintentar</button></article>
  return <article className={`answer ${selected ? 'answer-selected' : ''}`}>
    <div className="markdown"><ReactMarkdown components={{ img: () => null, a: ({ href, children }) => {
      const safe = href && /^https?:\/\//i.test(href)
      return safe ? <a href={href} target="_blank" rel="noopener noreferrer">{children}</a> : <span>{children}</span>
    } }}>{message.content}</ReactMarkdown></div>
    {message.result && <div className="answer-footer">
      <span>{message.result.sources.length} fuentes · {message.result.trace.template_answer ? 'Respuesta desde metadatos verificados' : message.result.trace.generation_status === 'skipped' ? 'Sin generación del modelo' : `${message.result.trace.timings_ms.generation} ms de generación`}</span>
      <button aria-pressed={selected} onClick={() => onEvidence(message.id)}>Ver evidencia</button>
      <button onClick={() => void copy()} aria-label="Copiar respuesta">Copiar</button>
    </div>}
    {copyStatus && <small role="status">{copyStatus}</small>}
  </article>
}
