import type { Finding } from '../types/api'

export function validIPv4(value: string) {
  const octets = value.trim().split('.')
  return octets.length === 4 && octets.every(part => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255)
}

export function simulatedConversationKey(runId: string, target: string, findingId: string) {
  return `${runId}:${target}:${findingId}`
}

export function simulationAnswer(finding: Finding, target: string, text: string) {
  if (/mitig|correg|soluci|actualiz/i.test(text)) {
    return `${finding.fix}\n\nValida la versión afectada antes de aplicar cambios.`
  }
  if (/valid|confirm|nmap|evidencia/i.test(text)) {
    return `Valida el producto y la versión instalada frente al aviso del fabricante. Un puerto abierto o un banner no demuestra que ${finding.id} sea explotable. Esta demostración no ejecuta comprobaciones reales.`
  }
  return `${finding.impact}\n\nReferencia ilustrativa: ${finding.id} · CVSS ${finding.score}. Este hallazgo no confirma una vulnerabilidad en ${target}.`
}
