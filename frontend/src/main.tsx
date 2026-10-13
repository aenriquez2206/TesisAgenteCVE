import React, { useEffect, useState, useRef } from 'react'
import { createRoot } from 'react-dom/client'
import { fetchHealth } from './api/client'
import { ChatMessage } from './components/ChatMessage'
import { Evidence } from './components/Evidence'
import { usePanelFocus } from './hooks/usePanelFocus'
import { useConversations } from './hooks/useConversations'
import type { DetectionRun, Finding, Health, SimulatedConversation, SimulatedMessage } from './types/api'
import './styles/main.css'
import { DetectionView } from './components/DetectionView'
import { SimulationChat } from './components/SimulationChat'
import { simulatedConversationKey, simulationAnswer } from './state/detection'

function App() {
  const { conversations, selected, setSelected, active, busy, pendingId, send, retry, newConversation, storageWarning } = useConversations()
  const [question, setQuestion] = useState('')
  const [health, setHealth] = useState<Health | null>(null)
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [evidenceOpen, setEvidenceOpen] = useState(false)
  const [evidenceId, setEvidenceId] = useState<string | null>(null)
  const [section, setSection] = useState<'detection' | 'queries'>('detection')
  const [run, setRun] = useState<DetectionRun | null>(null)
  const [simulations, setSimulations] = useState<Record<string, SimulatedConversation>>({})
  const [simulatedId, setSimulatedId] = useState<string | null>(null)
  const composer = useRef<HTMLTextAreaElement>(null)
  const sidebarRef = usePanelFocus(sidebarOpen, () => setSidebarOpen(false))
  const evidenceRef = usePanelFocus(evidenceOpen, () => setEvidenceOpen(false))
  useEffect(() => { setEvidenceId(null) }, [selected])
  useEffect(() => {
    let alive = true
    const poll = () => void fetchHealth().then(value => { if (alive) setHealth(value) }).catch(() => { if (alive) setHealth(null) })
    poll()
    const timer = setInterval(poll, 30000)
    return () => { alive = false; clearInterval(timer) }
  }, [])
  const evidenceMessage = active?.messages.find(m => m.id === evidenceId && m.result)
    || [...(active?.messages || [])].reverse().find(m => m.result)
  const latest = evidenceMessage?.result
  const ready = health?.chroma === 'available' && health.collection_status === 'available' && health.embeddings === 'available' && health.llm === 'available'
  function submit(event: React.FormEvent) {
    event.preventDefault()
    if (!question.trim() || busy) return
    void send(question)
    setQuestion('')
  }
  const simulated = simulatedId ? simulations[simulatedId] : null
  const openSimulation = (finding: Finding) => {
    if (!run) return
    const id = simulatedConversationKey(run.id, run.target, finding.id)
    setSimulations(previous => previous[id] ? previous : { ...previous, [id]: { id, finding, runId: run.id, target: run.target, messages: [] } })
    setSimulatedId(id); setSection('queries'); setEvidenceOpen(false)
  }
  const sendSimulated = (content: string) => {
    if (!simulated) return
    const text = content.trim()
    if (!text) return
    const f = simulated.finding
    const answer = simulationAnswer(f, simulated.target, text)
    const user: SimulatedMessage = { id: crypto.randomUUID(), role: 'user', content: text }
    const assistant: SimulatedMessage = { id: crypto.randomUUID(), role: 'assistant', content: answer }
    setSimulations(previous => ({ ...previous, [simulated.id]: { ...simulated, messages: [...simulated.messages, user, assistant] } }))
  }
  return <div className="app">
    <aside ref={sidebarRef} id="history-panel" role={sidebarOpen ? 'dialog' : undefined} aria-modal={sidebarOpen || undefined} className={`sidebar ${sidebarOpen ? 'open' : ''}`} aria-label="Historial de conversaciones">
      <button className="mobile-close" onClick={() => setSidebarOpen(false)} aria-label="Cerrar historial">✕</button>
      <div className="brand"><div className="shield" aria-hidden="true">◈</div></div>
      <nav className="section-nav" aria-label="Secciones"><button className={section === 'queries' ? 'selected' : ''} onClick={() => { setSection('queries'); setSimulatedId(null); setEvidenceOpen(false) }}>▤ &nbsp; Consultas</button><button className={section === 'detection' ? 'selected' : ''} onClick={() => { setSection('detection'); setEvidenceOpen(false) }}>◎ &nbsp; Detección</button></nav>
      <button className="primary" onClick={() => { setSection('queries'); setSimulatedId(null); newConversation(); setSidebarOpen(false); setTimeout(() => composer.current?.focus(), 0) }}>+ Nueva conversación</button>
      <nav className="history" aria-label="Conversaciones">{conversations.map(c =>
        <button key={c.id} className={selected === c.id ? 'selected' : ''} onClick={() => { setSelected(c.id); setSimulatedId(null); setSection('queries'); setSidebarOpen(false) }}>{c.title}</button>)}</nav>
      <div className="connection"><span className={`dot ${ready ? 'online' : ''}`} />{ready ? 'Servicios disponibles' : 'Servicios no disponibles'}
        {health && !ready && <small>Chroma: {health.chroma} · Colección: {health.collection_status} · Embeddings: {health.embeddings} · LLM: {health.llm}</small>}</div>
    </aside>
    <main className="main">
      <header className="header"><div className="mobile-controls"><button aria-expanded={sidebarOpen} aria-controls="history-panel" onClick={() => { setEvidenceOpen(false); setSidebarOpen(v => !v) }} aria-label="Abrir menú"><svg aria-hidden="true" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 6h18M3 12h18M3 18h18" /></svg></button></div><div><h1>{section === 'detection' ? 'Detección' : simulated ? simulated.finding.id : 'Consultas'}</h1><small>{section === 'detection' ? 'Descubrimiento de vulnerabilidades' : simulated ? 'Chat de demostración · respuestas predefinidas' : 'Consulta el catálogo CVE local con fuentes verificables'}</small></div>{section === 'queries' && !simulated && <button className="evidence-toggle" aria-expanded={evidenceOpen} aria-controls="evidence-panel" onClick={() => { setSidebarOpen(false); setEvidenceOpen(v => !v) }}>Evidencia</button>}</header>
      {storageWarning && <p className="storage-warning" role="status">{storageWarning}</p>}
      <div hidden={section !== 'detection'}><DetectionView run={run} onRun={setRun} onSelect={openSimulation} /></div>
      {section === 'queries' && simulated && <SimulationChat conversation={simulated} onBack={() => { setSection('detection'); setSimulatedId(null) }} onSend={sendSimulated} />}
      {section === 'queries' && !simulated && <>
      <section className="chat" aria-live="polite">
        {!active?.messages.length && <div className="welcome"><div className="welcome-icon">◇</div><h2>¿Qué vulnerabilidad quieres investigar?</h2><p>Pregunta por un CVE, producto o patrón de ataque. Las respuestas mostrarán los registros recuperados.</p></div>}
        {active?.messages.map(message => <ChatMessage key={message.id} message={message} onRetry={retry} busy={busy} selected={message.id === evidenceMessage?.id}
          onEvidence={id => { setEvidenceId(id); if (window.matchMedia('(max-width:1150px)').matches) { setSidebarOpen(false); setEvidenceOpen(true) } }} />)}
        {busy && pendingId === selected && <div className="loading" role="status"><span className="spinner"/> Preparando consulta, recuperando evidencia y generando respuesta…</div>}
      </section>
      <form className="composer" onSubmit={submit}><div className="input"><textarea ref={composer} maxLength={4000} aria-label="Tu consulta" placeholder="Pregunta sobre un CVE, producto o vulnerabilidad…" value={question} onChange={e => setQuestion(e.target.value)} onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) { e.preventDefault(); e.currentTarget.form?.requestSubmit() } }} disabled={busy} /><button className="send" type="submit" disabled={busy || !question.trim()} aria-label="Enviar consulta"><svg aria-hidden="true" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="m4 4 16 8-16 8 3-8-3-8Z M7 12h13" /></svg></button></div><small>Enter para enviar · Shift+Enter para nueva línea</small></form>
      </>}
    </main>
    {section === 'queries' && !simulated && <section ref={evidenceRef} id="evidence-panel" aria-label="Evidencia de la respuesta" role={evidenceOpen ? 'dialog' : undefined} aria-modal={evidenceOpen || undefined} className={`evidence-container ${evidenceOpen ? 'open' : ''}`}><button className="evidence-close" onClick={() => setEvidenceOpen(false)} aria-label="Cerrar evidencia">✕</button><Evidence result={latest} /></section>}
  </div>
}


createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>)
