import test from 'node:test'
import assert from 'node:assert/strict'
import { validIPv4, simulatedConversationKey, simulationAnswer } from '../src/state/detection.ts'

test('IPv4 validation accepts four numeric octets in range', () => {
  assert.equal(validIPv4('192.168.1.10'), true)
  assert.equal(validIPv4('0.0.0.0'), true)
  assert.equal(validIPv4('255.255.255.255'), true)
})

test('IPv4 validation rejects empty, incomplete, non-numeric and out-of-range input', () => {
  for (const value of ['', '192.168.1', '192.168.1.1.4', 'a.1.2.3', '999.1.1.1', '1.2.3.-1', '1.2.3.']) {
    assert.equal(validIPv4(value), false, value)
  }
})

const finding = { id: 'CVE-2021-41773', name: 'Traversal', service: 'Apache', port: '80',
  score: '7.5', level: 'Alta', impact: 'Acceso a archivos en ciertas condiciones.', fix: 'Actualizar Apache.' }

test('simulation labels findings as illustrative and separates validation from impact', () => {
  const answer = simulationAnswer(finding, '192.168.1.10', '¿Cuál es el impacto?')
  assert.match(answer, /Referencia ilustrativa/)
  assert.match(answer, /no confirma una vulnerabilidad en 192\.168\.1\.10/)
  const validation = simulationAnswer(finding, '192.168.1.10', '¿Cómo valido el hallazgo?')
  assert.match(validation, /no demuestra que CVE-2021-41773 sea explotable/)
  assert.match(validation, /no ejecuta comprobaciones reales/)
})

test('simulation mitigation asks to validate the affected version', () => {
  assert.match(simulationAnswer(finding, 'target', '¿Cómo puedo mitigarla?'),
    /Actualizar Apache\.\n\nValida la versión afectada/)
})

test('simulation conversations are isolated by run, target and finding', () => {
  const key = simulatedConversationKey('run-1', '192.168.1.10', finding.id)
  assert.notEqual(key, simulatedConversationKey('run-2', '192.168.1.10', finding.id))
  assert.notEqual(key, simulatedConversationKey('run-1', '192.168.1.11', finding.id))
  assert.notEqual(key, simulatedConversationKey('run-1', '192.168.1.10', 'CVE-2019-0708'))
})
