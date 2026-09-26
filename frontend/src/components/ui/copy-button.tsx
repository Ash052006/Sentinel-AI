import { useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { Button } from './button'
import { cn } from '../../lib/utils'

async function copyText(text: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text)
    return
  }
  const el = document.createElement('textarea')
  el.value = text
  el.setAttribute('readonly', '')
  el.style.position = 'absolute'
  el.style.left = '-9999px'
  document.body.appendChild(el)
  el.select()
  document.execCommand('copy')
  document.body.removeChild(el)
}

export function CopyButton({
  value,
  className,
  label,
}: {
  value: string
  className?: string
  label?: string
}) {
  const [copied, setCopied] = useState(false)

  async function handleCopy(): Promise<void> {
    try {
      await copyText(value)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1200)
    } catch {
      /* clipboard unavailable */
    }
  }

  return (
    <Button
      variant="ghost"
      size="sm"
      className={cn('h-5 px-1 text-[11px]', className)}
      onClick={() => void handleCopy()}
      aria-label={label ?? 'Copy to clipboard'}
    >
      {copied ? (
        <Check className="h-3 w-3 text-low" />
      ) : (
        <Copy className="h-3 w-3" />
      )}
      {copied ? 'copied' : 'copy'}
    </Button>
  )
}