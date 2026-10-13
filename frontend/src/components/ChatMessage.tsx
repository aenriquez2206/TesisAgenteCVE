import ReactMarkdown from 'react-markdown'
import type { Message } from '../types/api'

export function ChatMessage({ message, onRetry }: { message: Message; onRetry: () => void }) {
  if (message.role === 'user') return <div className="user-message">{message.content}</div>
  if (message.error) return <article className="answer error" role="alert"><strong>No se completó la consulta</strong><p>{message.error}</p><button onClick={onRetry}>Reintentar</button></article>
  return <article className="answer">
    <div className="markdown"><ReactMarkdown components={{ a: ({ href, children }) => {
      const safe = href && /^https?:\/\//i.test(href)
      return safe ? <a href={href} target="_blank" rel="noopener noreferrer">{children}</a> : <span>{children}</span>
    } }}>{message.content}</ReactMarkdown></div>
    {message.result && <div className="answer-footer">
      <span>{message.result.sources.length} fuentes · {message.result.trace.timings_ms.generation} ms de generación</span>
      <button onClick={() => void navigator.clipboard.writeText(message.content)} aria-label="Copiar respuesta">Copiar</button>
    </div>}
  </article>
}
