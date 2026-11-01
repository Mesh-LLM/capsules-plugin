// "Save receipt page" on an Exchanges row (Mesh-LLM/capsules-plugin#96,
// Steven's 10-29 ruling, item 1): this exchange's receipt as one .html page
// for an outside party, carrying the bundle the node served and checking it
// when it opens (`saved-pages.ts`). The page, not this button, checks the
// bundle. Fetching can make the node sign a checkpoint, so it runs on a click.
import { useState } from 'react'
import { Button } from '@/components/ui/button'
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'
import { fetchReceipt } from '@/features/capsules/api/receiptClient'
import { saveTextFile } from '@/features/capsules/lib/exchange-export'
import { NO_RECORD_REASONS, receiptRequest } from '@/features/capsules/lib/receipt-view'
import { NO_PAID_DEAL_WHY, receiptPage, type ReceiptSource } from '@/features/capsules/lib/saved-pages'

/** The sentence under the button: what the page is, for whom. */
export const RECEIPT_PAGE_SENTENCE =
  'A page for anyone: this node’s receipt for this exchange. It checks itself when opened, offline, no account needed, and holds the receipt’s bytes unchanged. Not included: the text, or proof the answer was right.'

async function receiptSource(row: PaneCRow): Promise<ReceiptSource> {
  const request = receiptRequest(row)
  if (!request) return { kind: 'no_record', why: NO_PAID_DEAL_WHY }
  const fetched = await fetchReceipt(request)
  if (fetched.kind === 'unavailable') throw new Error(fetched.message)
  if (fetched.kind === 'bundle') return fetched
  return { kind: NO_RECORD_REASONS.includes(fetched.why) ? 'no_record' : 'no_receipt_yet', why: fetched.why }
}

export function SaveReceiptPage({ row, exchangeKey }: { row: PaneCRow; exchangeKey: string }) {
  const [saving, setSaving] = useState(false)
  const [note, setNote] = useState<string | null>(null)

  async function save() {
    setSaving(true)
    setNote(null)
    try {
      const savedAt = new Date().toISOString().replace(/\.\d+Z$/, 'Z')
      const page = receiptPage(await receiptSource(row), exchangeKey, savedAt)
      if (!saveTextFile(page.fileName, page.html, 'text/html')) setNote('This browser could not save the page.')
    } catch (error) {
      setNote(`Could not save the page: ${error instanceof Error ? error.message : 'this node did not answer'}.`)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      <Button
        className="ui-control h-7 gap-1 rounded-[var(--radius)] px-2 text-[length:var(--density-type-caption)]"
        disabled={saving}
        onClick={() => void save()}
        size="sm"
        type="button"
        variant="outline"
      >
        Save receipt page
      </Button>
      {note ? (
        <span className="text-xs text-fg-faint" role="status">
          {note}
        </span>
      ) : null}
    </div>
  )
}
