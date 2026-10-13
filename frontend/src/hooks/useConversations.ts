import { useEffect, useRef, useState } from 'react'
import { sendChat } from '../api/client'
import type { Conversation, Message } from '../types/api'

const key = 'cve-intelligence-conversations-v1'

function initial(): Conversation[] {
  try {
    const value = JSON.parse(localStorage.getItem(key) || '[]')
    if (Array.isArray(value) && value.every(c => typeof c.id === 'string' && Array.isArray(c.messages))) return value
  } catch { /* Damaged local history is ignored. */ }
  return []
}

export function useConversations() {
  const [conversations, setConversations] = useState<Conversation[]>(initial)
  const [selected, setSelected] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const lock = useRef(false)
  useEffect(() => { try { localStorage.setItem(key, JSON.stringify(conversations)) } catch { /* Storage may be full. */ } }, [conversations])
  const active = conversations.find(c => c.id === selected)

  function newConversation() { setSelected(null) }

  async function send(text: string, retryPrevious = false) {
    const content = text.trim()
    if (!content || lock.current) return
    lock.current = true
    setBusy(true)
    const id = selected || crypto.randomUUID()
    const existing = conversations.find(c => c.id === id)
    const previousMessages = (existing?.messages || []).filter(m => !m.error)
    const history = retryPrevious ? previousMessages.slice(0, -1) : previousMessages
    const user: Message = { id: crypto.randomUUID(), role: 'user', content }
    const title = existing?.title || content.slice(0, 48)
    setConversations(previous => [{ id, title, updatedAt: Date.now(), messages: [...history, user] }, ...previous.filter(c => c.id !== id)])
    setSelected(id)
    try {
      const result = await sendChat(content, id, history)
      const assistant: Message = { id: crypto.randomUUID(), role: 'assistant', content: result.answer, result }
      setConversations(previous => previous.map(c => c.id === id ? { ...c, updatedAt: Date.now(), messages: [...c.messages, assistant] } : c))
    } catch (error) {
      const assistant: Message = { id: crypto.randomUUID(), role: 'assistant', content: '', error: error instanceof Error ? error.message : 'Error desconocido' }
      setConversations(previous => previous.map(c => c.id === id ? { ...c, messages: [...c.messages, assistant] } : c))
    } finally {
      lock.current = false
      setBusy(false)
    }
  }

  function retry() {
    if (!active || busy) return
    const last = [...active.messages].reverse().find(m => m.role === 'user')
    if (!last) return
    void send(last.content, true)
  }

  return { conversations, selected, setSelected, active, busy, send, retry, newConversation }
}
