import { useState, useRef, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  Loader2,
  Maximize2,
  Send,
  Sparkles,
  X,
  ArrowRight,
  Bot,
  User as UserIcon,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  RotateCcw,
} from 'lucide-react'
import { socApi } from '../api/soc'
import type { SOCQueryResponse } from '../types/api'
import { cn } from '../lib/utils'
import { synthesizeSocResponse, isConversationalQuery, type AssistantAnalysis } from '../lib/soc-assistant'

interface ItemView {
  id: string
  label: string
  meta: string
  link: string | null
}

function describeItem(resource: string, row: Record<string, unknown>): ItemView {
  switch (resource) {
    case 'detections':
      return {
        id: String(row.detection_id ?? row.id ?? ''),
        label: String(row.rule_id ?? ''),
        meta: String(row.severity ?? ''),
        link: '/detections',
      }
    case 'correlations':
      return {
        id: String(row.correlation_id ?? row.id ?? ''),
        label: `Correlated incidents (${row.members_count ?? (Array.isArray(row.members) ? row.members.length : 1)})`,
        meta: String(row.status ?? ''),
        link: `/incidents/${String(row.correlation_id ?? row.id ?? '')}`,
      }
    case 'risk_assessments':
      return {
        id: String(row.risk_assessment_id ?? row.id ?? ''),
        label: `Score ${row.score ?? '—'}`,
        meta: String(row.level ?? ''),
        link: '/risk',
      }
    case 'incident_memories':
      return {
        id: String(row.memory_id ?? row.id ?? ''),
        label: String(row.title ?? ''),
        meta: String(row.memory_type ?? ''),
        link: `/search?q=${encodeURIComponent(String(row.title ?? ''))}`,
      }
    default:
      return {
        id: String(row.id ?? ''),
        label: '',
        meta: '',
        link: null,
      }
  }
}

const QUICK_PROMPTS = [
  'hello',
  'what vulnerabilities exist?',
  'recent detections',
  'recent correlations',
]

interface ChatMessage {
  id: string
  sender: 'user' | 'assistant'
  text: string
  timestamp: string
  analysis?: AssistantAnalysis
  response?: SOCQueryResponse
}

export function FloatingAskSoc() {
  const [isOpen, setIsOpen] = useState(false)
  const [inputQuery, setInputQuery] = useState('')
  const [status, setStatus] = useState<'idle' | 'loading' | 'error' | 'done'>('idle')
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [showEvidence, setShowEvidence] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const navigate = useNavigate()

  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 50)
    }
  }, [isOpen])

  useEffect(() => {
    if (typeof messagesEndRef.current?.scrollIntoView === 'function') {
      messagesEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [messages, status])

  // Close on Escape key
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape' && isOpen) {
        setIsOpen(false)
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen])

  async function handleQuery(queryText: string) {
    const q = queryText.trim()
    if (!q) return

    const userMsg: ChatMessage = {
      id: `u-${Date.now()}`,
      sender: 'user',
      text: q,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    }

    setMessages((prev) => [...prev, userMsg])
    setInputQuery('')
    setStatus('loading')

    // First, check if this is a conversational query (greetings, vulnerability guidance, etc.)
    if (isConversationalQuery(q)) {
      const conversational = synthesizeSocResponse(q, null)
      const assistantMsg: ChatMessage = {
        id: `a-${Date.now()}`,
        sender: 'assistant',
        text: conversational.summary,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        analysis: conversational,
      }
      setMessages((prev) => [...prev, assistantMsg])
      setStatus('done')
      return
    }

    // Telemetry-grounded query
    try {
      const resp = await socApi.query(q)
      const analysis = synthesizeSocResponse(q, resp)

      const assistantMsg: ChatMessage = {
        id: `a-${Date.now()}`,
        sender: 'assistant',
        text: analysis.summary,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        analysis,
        response: resp,
      }

      setMessages((prev) => [...prev, assistantMsg])
      setStatus('done')
    } catch (err) {
      setStatus('error')
      const errorMsg = err instanceof Error ? err.message : 'The SOC querier could not answer.'

      const assistantErr: ChatMessage = {
        id: `a-err-${Date.now()}`,
        sender: 'assistant',
        text: `I encountered an issue querying the SOC pipeline: ${errorMsg}`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      }
      setMessages((prev) => [...prev, assistantErr])
    }
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    void handleQuery(inputQuery)
  }

  function handleReset() {
    setMessages([])
    setStatus('idle')
    setInputQuery('')
  }

  return (
    <>
      {/* Floating Action Button */}
      <div className="fixed bottom-6 right-6 z-40">
        <button
          type="button"
          data-testid="floating-ask-soc-trigger"
          onClick={() => setIsOpen((prev) => !prev)}
          className={cn(
            'group flex items-center gap-2 rounded-full border px-3.5 py-2.5 text-xs font-medium shadow-2xl backdrop-blur-md transition-all duration-200 active:scale-95 focus:outline-none focus:ring-2 focus:ring-accent',
            isOpen
              ? 'border-accent bg-surface-2 text-ink ring-2 ring-accent/30'
              : 'border-accent/40 bg-surface-1/95 text-ink hover:border-accent hover:bg-surface-2 hover:shadow-accent/20',
          )}
          aria-label={isOpen ? 'Close Ask SOC assistant' : 'Open Ask SOC assistant'}
          title="Ask SOC Personal Assistant"
        >
          <div className="relative flex h-6 w-6 items-center justify-center rounded-full bg-accent/20 text-accent group-hover:bg-accent group-hover:text-surface-0 transition-colors">
            <Sparkles className="h-3.5 w-3.5" />
            <span className="absolute -top-0.5 -right-0.5 h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
          </div>
          <span className="font-semibold tracking-wide">Ask SOC</span>
        </button>
      </div>

      {/* Floating Assistant Dialog Box */}
      {isOpen && (
        <div
          data-testid="floating-ask-soc-box"
          className="fixed bottom-20 right-6 z-40 w-[450px] max-w-[calc(100vw-2rem)] h-[580px] flex flex-col rounded-xl border border-edge bg-surface-1/95 shadow-2xl backdrop-blur-md overflow-hidden animate-in fade-in slide-in-from-bottom-4 duration-150"
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-edge-soft bg-surface-2/80 px-4 py-2.5">
            <div className="flex items-center gap-2">
              <div className="flex h-6 w-6 items-center justify-center rounded-md bg-accent/20 text-accent">
                <Bot className="h-3.5 w-3.5" />
              </div>
              <div>
                <div className="flex items-center gap-1.5">
                  <span className="text-xs font-semibold text-ink">Ask SOC Copilot</span>
                  <span className="rounded bg-accent/10 px-1.5 py-0.2 font-mono text-[9px] font-medium uppercase tracking-wider text-accent border border-accent/20">
                    Personal Assistant
                  </span>
                </div>
                <div className="text-[10px] text-ink-faint flex items-center gap-1">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 inline-block" />
                  <span>Interactive Security Guidance & Telemetry</span>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-1">
              {messages.length > 0 && (
                <button
                  type="button"
                  onClick={handleReset}
                  className="rounded p-1 text-ink-faint transition hover:bg-surface-3 hover:text-ink"
                  title="Clear conversation"
                  aria-label="Clear conversation"
                >
                  <RotateCcw className="h-3.5 w-3.5" />
                </button>
              )}
              <Link
                to={`/search${inputQuery ? `?q=${encodeURIComponent(inputQuery)}` : ''}`}
                onClick={() => setIsOpen(false)}
                title="Open Dedicated Ask SOC Page"
                className="flex items-center gap-1 rounded px-2 py-1 text-xs text-accent transition hover:bg-surface-3"
                aria-label="Open dedicated Ask SOC page"
              >
                <Maximize2 className="h-3.5 w-3.5" />
                <span className="hidden sm:inline text-[11px] font-medium">Open Page</span>
              </Link>
              <button
                type="button"
                onClick={() => setIsOpen(false)}
                className="rounded p-1 text-ink-faint transition hover:bg-surface-3 hover:text-ink"
                aria-label="Close Ask SOC box"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>

          {/* Conversation Area */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {messages.length === 0 ? (
              <div className="space-y-4 py-3">
                <div className="flex gap-3">
                  <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-accent/20 text-accent">
                    <Sparkles className="h-4 w-4" />
                  </div>
                  <div className="space-y-1.5">
                    <div className="text-xs font-semibold text-ink">Hello! I'm your Personal SOC Assistant</div>
                    <p className="text-xs text-ink-dim leading-relaxed">
                      You can ask me anything — from general questions about vulnerabilities and CVEs to live telemetry investigations, incident correlations, and mitigation advice.
                    </p>
                  </div>
                </div>

                <div className="pt-2">
                  <span className="text-[10px] font-semibold uppercase tracking-wider text-ink-faint block mb-2">
                    Try asking
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {QUICK_PROMPTS.map((prompt) => (
                      <button
                        key={prompt}
                        type="button"
                        onClick={() => void handleQuery(prompt)}
                        className="rounded-full border border-edge bg-surface-2/70 px-3 py-1 text-[11px] text-ink-dim hover:border-accent hover:text-accent hover:bg-surface-3 transition"
                      >
                        {prompt}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              messages.map((msg) => (
                <div key={msg.id} className="space-y-2">
                  {msg.sender === 'user' ? (
                    <div className="flex justify-end gap-2">
                      <div className="max-w-[85%] rounded-2xl rounded-tr-sm bg-accent/20 border border-accent/30 px-3.5 py-2 text-xs text-ink">
                        {msg.text}
                      </div>
                      <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-surface-3 text-ink-dim">
                        <UserIcon className="h-3.5 w-3.5" />
                      </div>
                    </div>
                  ) : (
                    <div className="flex gap-2.5">
                      <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-accent/20 text-accent">
                        <Bot className="h-3.5 w-3.5" />
                      </div>
                      <div className="min-w-0 flex-1 space-y-2.5">
                        {msg.analysis ? (
                          <div className="space-y-2.5 rounded-xl border border-edge bg-surface-2/50 p-3 text-xs">
                            {/* Verdict Banner */}
                            <div className="flex items-center gap-1.5">
                              <span
                                className={cn(
                                  'h-2 w-2 rounded-full',
                                  msg.analysis.severityLevel === 'critical'
                                    ? 'bg-critical'
                                    : msg.analysis.severityLevel === 'high'
                                      ? 'bg-amber-500'
                                      : 'bg-emerald-500',
                                )}
                              />
                              <span className="font-semibold text-ink text-xs">
                                {msg.analysis.verdict}
                              </span>
                            </div>

                            {/* Headline */}
                            <div className="font-mono text-[10px] text-accent">
                              {msg.analysis.headline}
                            </div>

                            {/* Assistant Synthesis Body */}
                            <p className="text-xs text-ink-dim leading-relaxed">
                              {msg.analysis.summary}
                            </p>

                            {/* Recommendations */}
                            {msg.analysis.recommendations.length > 0 && (
                              <div className="space-y-1 pt-1 border-t border-edge-soft">
                                <span className="text-[10px] font-semibold uppercase tracking-wider text-ink-faint block">
                                  Recommended Next Steps
                                </span>
                                <ul className="space-y-1">
                                  {msg.analysis.recommendations.map((rec, idx) => (
                                    <li
                                      key={idx}
                                      className="flex items-start gap-1.5 text-[11px] text-ink-dim"
                                    >
                                      <CheckCircle2 className="h-3 w-3 text-emerald-400 shrink-0 mt-0.5" />
                                      <span>{rec}</span>
                                    </li>
                                  ))}
                                </ul>
                              </div>
                            )}

                            {/* Large Content Link Button */}
                            {msg.response &&
                              msg.response.found &&
                              ((msg.response.total !== null && msg.response.total > 3) ||
                                msg.response.items.length > 3) && (
                                <div className="mt-2 rounded-lg border border-accent/30 bg-accent/10 p-2.5 space-y-1.5">
                                  <div className="text-[11px] font-semibold text-accent">
                                    Large Result Set ({msg.response.total ?? msg.response.items.length} records)
                                  </div>
                                  <p className="text-[10px] text-ink-dim">
                                    Full telemetry breakdown with sortable tables and export is available on the dedicated page.
                                  </p>
                                  <div className="flex items-center gap-2 pt-1">
                                    <button
                                      type="button"
                                      onClick={() => {
                                        setIsOpen(false)
                                        navigate(`/search?q=${encodeURIComponent(msg.text)}`)
                                      }}
                                      className="inline-flex items-center gap-1 rounded bg-accent px-2.5 py-1 text-[11px] font-medium text-surface-0 hover:bg-accent/90 transition"
                                    >
                                      <span>Open in Ask SOC Page</span>
                                      <ArrowRight className="h-3 w-3" />
                                    </button>
                                  </div>
                                </div>
                              )}

                            {/* Collapsible Telemetry Evidence (when telemetry exists) */}
                            {msg.response && msg.response.items.length > 0 && (
                              <div className="pt-1 border-t border-edge-soft">
                                <button
                                  type="button"
                                  onClick={() => setShowEvidence((prev) => !prev)}
                                  className="flex items-center justify-between w-full text-[10px] font-mono text-ink-faint hover:text-ink transition py-1"
                                >
                                  <span>
                                    Cited Telemetry Evidence ({msg.response.items.length} records)
                                  </span>
                                  {showEvidence ? (
                                    <ChevronUp className="h-3 w-3" />
                                  ) : (
                                    <ChevronDown className="h-3 w-3" />
                                  )}
                                </button>

                                {showEvidence && (
                                  <div className="space-y-1.5 mt-1.5">
                                    {msg.response.items.slice(0, 4).map((row, idx) => {
                                      const item = describeItem(
                                        msg.response!.metadata.resource,
                                        row,
                                      )
                                      return (
                                        <div
                                          key={`${item.id}-${idx}`}
                                          className="flex items-center justify-between gap-2 rounded border border-edge-soft bg-surface-1 px-2 py-1 text-[11px]"
                                        >
                                          <div className="min-w-0 truncate">
                                            <span className="font-mono text-ink">{item.id || '—'}</span>
                                            {item.label && (
                                              <span className="ml-1.5 text-ink-faint text-[10px]">
                                                {item.label}
                                              </span>
                                            )}
                                          </div>
                                          <div className="flex items-center gap-1 shrink-0">
                                            {item.meta && (
                                              <span className="rounded border border-edge px-1 font-mono text-[9px] uppercase text-ink-faint">
                                                {item.meta}
                                              </span>
                                            )}
                                            {item.link && (
                                              <Link
                                                to={item.link}
                                                onClick={() => setIsOpen(false)}
                                                className="text-accent text-[10px] hover:underline"
                                              >
                                                Inspect →
                                              </Link>
                                            )}
                                          </div>
                                        </div>
                                      )
                                    })}
                                  </div>
                                )}
                              </div>
                            )}

                            {/* Suggested Follow-ups */}
                            {msg.analysis.followUps.length > 0 && (
                              <div className="flex flex-wrap gap-1 pt-1">
                                {msg.analysis.followUps.map((fu) => (
                                  <button
                                    key={fu}
                                    type="button"
                                    onClick={() => void handleQuery(fu)}
                                    className="rounded-full border border-edge-soft bg-surface-1 px-2 py-0.5 text-[10px] text-ink-dim hover:border-accent hover:text-accent transition"
                                  >
                                    + {fu}
                                  </button>
                                ))}
                              </div>
                            )}
                          </div>
                        ) : (
                          <div className="rounded-xl border border-edge bg-surface-2/50 p-3 text-xs text-ink-dim leading-relaxed">
                            {msg.text}
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              ))
            )}

            {status === 'loading' && (
              <div className="flex items-center gap-2.5 text-xs text-ink-faint py-2">
                <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-accent/20 text-accent">
                  <Bot className="h-3.5 w-3.5" />
                </div>
                <div className="flex items-center gap-2 rounded-xl border border-edge bg-surface-2/40 px-3 py-2">
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-accent" />
                  <span>Analyzing inquiry & preparing security guidance...</span>
                </div>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Footer Controls & Input */}
          <div className="border-t border-edge-soft bg-surface-2/60 p-2.5 space-y-2">
            <div className="flex items-center justify-between text-[10px] text-ink-faint px-0.5">
              <span>Personal Security Assistant</span>
              <Link
                to={`/search${inputQuery ? `?q=${encodeURIComponent(inputQuery)}` : ''}`}
                onClick={() => setIsOpen(false)}
                className="text-accent hover:underline flex items-center gap-1 font-medium"
              >
                <span>Open Dedicated Ask SOC Page</span>
                <ArrowRight className="h-3 w-3" />
              </Link>
            </div>

            <form onSubmit={handleSubmit} className="flex gap-1.5">
              <input
                ref={inputRef}
                type="text"
                value={inputQuery}
                onChange={(e) => setInputQuery(e.target.value)}
                placeholder="Ask your SOC assistant (e.g. 'hello', 'about vulnerabilities')..."
                data-testid="floating-ask-soc-input"
                className="h-8 flex-1 rounded-md border border-edge bg-surface-0 px-2.5 text-xs text-ink placeholder:text-ink-faint outline-none focus:border-accent"
              />
              <button
                type="submit"
                disabled={status === 'loading' || !inputQuery.trim()}
                data-testid="floating-ask-soc-submit"
                className="inline-flex h-8 w-8 items-center justify-center rounded-md bg-accent text-surface-0 hover:bg-accent/90 disabled:opacity-40 transition shrink-0"
                aria-label="Send query"
              >
                <Send className="h-3.5 w-3.5" />
              </button>
            </form>
          </div>
        </div>
      )}
    </>
  )
}
