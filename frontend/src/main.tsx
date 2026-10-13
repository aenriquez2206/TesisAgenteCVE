import React, { useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { fetchHealth } from './api/client'
import { ChatMessage } from './components/ChatMessage'
import { Evidence } from './components/Evidence'
import { useConversations } from './hooks/useConversations'
import type { Health } from './types/api'
import './styles/main.css'

function App() {
  const { conversations, selected, setSelected, active, busy, send, retry, newConversation } = useConversations()
  const [question, setQuestion] = useState('')
  const [health, setHealth] = useState<Health | null>(null)
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [evidenceOpen, setEvidenceOpen] = useState(false)
  useEffect(() => {
    let alive = true
    const poll = () => void fetchHealth().then(value => { if (alive) setHealth(value) }).catch(() => { if (alive) setHealth(null) })
    poll()
    const timer = setInterval(poll, 30000)
    return () => { alive = false; clearInterval(timer) }
  }, [])
  const latest = [...(active?.messages || [])].reverse().find(m => m.result)?.result
  const ready = health?.chroma === 'available' && health.embeddings === 'available' && health.llm === 'available'
  function submit(event: React.FormEvent) {
    event.preventDefault()
    if (!question.trim() || busy) return
    void send(question)
    setQuestion('')
  }
  return <div className="app">
    <aside className={`sidebar ${sidebarOpen ? 'open' : ''}`} aria-label="Historial de conversaciones">
      <button className="mobile-close" onClick={() => setSidebarOpen(false)} aria-label="Cerrar historial">✕</button>
      <div className="brand"><div className="shield">C</div><div><strong>CVE Intelligence</strong><small>Investigación de vulnerabilidades</small></div></div>
      <button className="primary" onClick={() => { newConversation(); setSidebarOpen(false) }}>+ Nueva conversación</button>
      <nav className="history" aria-label="Conversaciones">{conversations.map(c =>
        <button key={c.id} className={selected === c.id ? 'selected' : ''} onClick={() => { setSelected(c.id); setSidebarOpen(false) }}>{c.title}</button>)}</nav>
      <div className="connection"><span className={`dot ${ready ? 'online' : ''}`} />{ready ? 'Servicios disponibles' : 'Servicios no disponibles'}
        {health && !ready && <small>Chroma: {health.chroma} · LLM: {health.llm}</small>}</div>
    </aside>
    <main className="main">
      <header className="header"><div className="mobile-controls"><button onClick={() => setSidebarOpen(v => !v)} aria-label="Abrir historial">☰</button></div><div><h1>Análisis de vulnerabilidades</h1><small>Consulta el catálogo CVE local con fuentes verificables</small></div><button className="evidence-toggle" onClick={() => setEvidenceOpen(v => !v)}>Evidencia</button></header>
      <section className="chat" aria-live="polite">
        {!active?.messages.length && <div className="welcome"><div className="welcome-icon">◇</div><h2>¿Qué vulnerabilidad quieres investigar?</h2><p>Pregunta por un CVE, producto o patrón de ataque. Las respuestas mostrarán los registros recuperados.</p></div>}
        {active?.messages.map(message => <ChatMessage key={message.id} message={message} onRetry={retry} />)}
        {busy && <div className="loading" role="status"><span className="spinner"/> Preparando consulta, recuperando evidencia y generando respuesta…</div>}
      </section>
      <form className="composer" onSubmit={submit}><div className="input"><textarea aria-label="Tu consulta" placeholder="Pregunta sobre un CVE, producto o vulnerabilidad…" value={question} onChange={e => setQuestion(e.target.value)} onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); e.currentTarget.form?.requestSubmit() } }} disabled={busy} /><button className="send" type="submit" disabled={busy || !question.trim()} aria-label="Enviar consulta">➤</button></div><small>Enter para enviar · Shift+Enter para nueva línea</small></form>
    </main>
    <div className={`evidence-container ${evidenceOpen ? 'open' : ''}`}><button className="evidence-close" onClick={() => setEvidenceOpen(false)} aria-label="Cerrar evidencia">✕</button><Evidence result={latest} /></div>
  </div>
}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>)
