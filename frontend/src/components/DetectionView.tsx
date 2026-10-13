import { useEffect, useState, type FormEvent } from 'react'
import type { DetectionRun, Finding } from '../types/api'
import { validIPv4 } from '../state/detection'

const findings: Finding[] = [
  { id: 'CVE-2021-41773', name: 'Traversal de directorios en Apache HTTP Server', service: 'Apache HTTP Server 2.4.49', port: '80 / TCP', score: '7.5', level: 'Alta', impact: 'En determinadas configuraciones, un atacante podría acceder a archivos fuera del directorio publicado.', fix: 'Actualizar Apache HTTP Server a una versión corregida y mantenida; revisar las reglas de acceso y restringir el contenido expuesto.' },
  { id: 'CVE-2021-44228', name: 'Log4Shell en Apache Log4j', service: 'Aplicación Java · Log4j 2', port: '8080 / TCP', score: '10.0', level: 'Crítica', impact: 'Una aplicación que usa una versión vulnerable de Log4j puede permitir ejecución remota de código bajo las condiciones del fallo.', fix: 'Identificar las dependencias de Log4j y actualizar a una versión corregida y compatible. Revisar registros, exposición y posibles indicadores de compromiso.' },
  { id: 'CVE-2019-0708', name: 'BlueKeep en servicios de escritorio remoto', service: 'Remote Desktop Services', port: '3389 / TCP', score: '9.8', level: 'Crítica', impact: 'Determinadas versiones vulnerables de Windows pueden permitir ejecución remota de código a través de RDP.', fix: 'Aplicar las actualizaciones del fabricante, limitar RDP a redes autorizadas y habilitar autenticación a nivel de red como medida adicional.' },
]
const steps = ['Preparando ejecución local simulada…', 'Descubriendo host objetivo…', 'Analizando puertos y servicios…', 'Identificando versiones de servicios…', 'Correlacionando servicios con CVEs de ejemplo…', 'Finalizado: 3 hallazgos ilustrativos.']
export function DetectionView({ run, onRun, onSelect }: { run: DetectionRun | null; onRun: (run: DetectionRun) => void; onSelect: (finding: Finding) => void }) {
  const [ip, setIp] = useState(''); const [error, setError] = useState(''); const [logs, setLogs] = useState<string[]>([]); const [progress, setProgress] = useState(0); const [running, setRunning] = useState(false); const [finished, setFinished] = useState(false)
  useEffect(() => { if (!running) return; let step = 0; let timer: ReturnType<typeof setTimeout>; let alive = true
    const advance = () => { if (!alive) return; setLogs(previous => [...previous, steps[step]]); setProgress(Math.round((step + 1) / steps.length * 100)); step++
      if (step < steps.length) timer = setTimeout(advance, 650)
      else timer = setTimeout(() => { if (alive) { onRun({ id: crypto.randomUUID(), target: ip.trim(), findings }); setRunning(false); setFinished(true) } }, 650)
    }; timer = setTimeout(advance, 100)
    return () => { alive = false; clearTimeout(timer) }
  }, [running])
  function submit(event: FormEvent) { event.preventDefault(); if (running) return; if (!validIPv4(ip)) { setError('Ingresa una dirección IPv4 válida, por ejemplo 192.168.1.10.'); return }
    setError(''); setLogs([]); setProgress(0); setFinished(false); setRunning(true)
  }
  return <div className="detection-content"><div className="detection-heading"><div><span className="eyebrow">DESCUBRIMIENTO DE VULNERABILIDADES</span><h2>De una IP a una respuesta.</h2><p>Simula la detección y analiza hallazgos ilustrativos con el agente.</p></div><span className="detection-icon" aria-hidden="true">◎</span></div>
    <section className="scanbox"><strong>⌖ &nbsp; Objetivo de detección</strong><form className="scan-form" onSubmit={submit}><input value={ip} onChange={e => setIp(e.target.value)} aria-label="Coloca la IP objetivo" placeholder="Coloca la IP objetivo" autoComplete="off" disabled={running} aria-invalid={!!error} aria-describedby={error ? 'ip-error' : 'ip-hint'} /><button className="primary" disabled={running}>{running ? 'Detectando…' : finished ? '◎  Detectar de nuevo' : '◎  Detectar'}</button></form>{error && <div id="ip-error" className="ip-error" role="alert">{error}</div>}<small id="ip-hint">Simulación local de Nmap · Datos de ejemplo · No se realizan conexiones al objetivo</small></section>
    {running && <section className="terminal" aria-live="polite"><div className="terminal-head"><span>● ● ● &nbsp; nmap / ejecución simulada</span><b>{progress}%</b></div>{logs.map((line, i) => <div className="terminal-line" key={i}>› {line}</div>)}<div className="progress-track"><div style={{ width: `${progress}%` }} /></div></section>}
    {!running && !run && <div className="detection-empty"><span aria-hidden="true">⌖</span><h3>Tu siguiente análisis empieza aquí</h3><p>Ingresa una dirección IP para simular la detección. Los CVE de ejemplo aparecerán en este espacio.</p></div>}
    {!running && run && <section className="finding-results"><div className="results-head"><div><h3>Vulnerabilidades encontradas <em>/ {run.findings.length}</em></h3><p>{run.target} · {run.findings.length} CVE de ejemplo · Selecciona un hallazgo para abrir su chat</p></div><span className="complete-badge">COMPLETADO</span></div><div className="finding-grid">{run.findings.map(f => <button className="finding-card" key={f.id} onClick={() => onSelect(f)}><span className={`severity ${f.level === 'Alta' ? 'high' : ''}`}>{f.level.toUpperCase()}</span><h4>{f.id}</h4><p>{f.name}</p><div className="finding-meta">{f.service}<br />{f.port} · CVSS {f.score}</div><div className="finding-action">Consultar con el agente <span>↗</span></div></button>)}</div><p className="sim-notice">Hallazgos ilustrativos: la asociación servicio–CVE debe validarse. Esta simulación no comprueba el objetivo.</p></section>}
  </div>
}
