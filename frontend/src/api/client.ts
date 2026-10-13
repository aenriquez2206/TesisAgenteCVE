import type { ChatResponse, Health, Message } from '../types/api'

const base = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '')

export async function sendChat(message: string, conversationId: string, history: Message[]): Promise<ChatResponse> {
  const response = await fetch(`${base}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, conversation_id: conversationId,
      history: history.slice(-10).map(item => ({ role: item.role, content: item.content })) }),
  })
  const body = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(body.message || `Error HTTP ${response.status}`)
  return body as ChatResponse
}

export async function fetchHealth(): Promise<Health> {
  const response = await fetch(`${base}/api/health`)
  if (!response.ok) throw new Error('No se pudo consultar la salud del servicio')
  return response.json() as Promise<Health>
}
