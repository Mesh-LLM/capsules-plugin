// The Exchanges table's "Export view" (a CSV of the current table, exactly
// what's on screen), Integrity's range-wide evidence file, and the file-save
// helper. A row's evidence for an outside party is its receipt page
// (`SaveReceiptPage.tsx`, Mesh-LLM/capsules-plugin#96), not a dump of the row.
import type { PaneAJson } from '@/features/capsules/api/sidecarTypes'
import type { ExchangeLedgerRow } from '@/features/capsules/lib/exchange-ledger'

const CSV_COLUMNS = ['Time', 'Exchange ID', 'Counterparty', 'Your role', 'Confirmed', 'Checks'] as const

function csvCell(value: string): string {
  if (!/[",\n]/.test(value)) return value
  return `"${value.replace(/"/g, '""')}"`
}

export function exchangeRowsToCsv(rows: readonly ExchangeLedgerRow[]): string {
  const lines = [CSV_COLUMNS.join(',')]
  for (const row of rows) {
    lines.push(
      [
        row.timestamp ?? '',
        row.exchangeKey,
        row.counterparty ?? '',
        row.roleTag,
        row.confirmed ? 'confirmed' : row.localOnly ? 'this node only' : 'not yet confirmed',
        row.checksText
      ]
        .map(csvCell)
        .join(',')
    )
  }
  return `${lines.join('\n')}\n`
}

/** Integrity's own "Save evidence file" (
 *  ledger-ux-from-the-user §7) -- covers the RANGE, not one exchange: this
 *  node's sealed chain plus the pane-a card facts (checkpoint/witnesses/
 *  continuity/owner) that back the registration copy and once-per-node
 *  facts rendered on the Integrity section. */
export function integrityEvidenceBundle(sealedRows: PaneAJson['rows'], card: PaneAJson['card']): string {
  return `${JSON.stringify(
    { schema: 'mesh-ledger-integrity-evidence/1', sealed: sealedRows, card: card ?? null },
    null,
    2
  )}\n`
}

export function saveTextFile(fileName: string, content: string, mediaType: string): boolean {
  if (
    typeof document === 'undefined' ||
    typeof URL === 'undefined' ||
    typeof URL.createObjectURL !== 'function' ||
    typeof URL.revokeObjectURL !== 'function'
  ) {
    return false
  }
  const url = URL.createObjectURL(new Blob([content], { type: mediaType }))
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = fileName
  anchor.rel = 'noopener'
  anchor.hidden = true
  document.body.append(anchor)
  anchor.click()
  anchor.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 0)
  return true
}
