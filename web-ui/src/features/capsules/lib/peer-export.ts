// Two distinct exports for the Peers table -- "Export view" (a CSV of the
// current table, exactly what's on screen) and "Save evidence file" (the portable
// evidence bundle: the underlying Pane B rows and the raw advertised-peer
// records, never a spreadsheet-shaped summary of the same facts).
import type { Peer } from '@/features/app-tabs/types'
import type { PaneBRow } from '@/features/capsules/api/sidecarTypes'
import type { PeerTableRowView } from '@/features/capsules/lib/peer-row-view'

const CSV_COLUMNS = [
  'Peer',
  'Exchanges',
  'Rewrote the record',
  'Left something out',
  'Swapped the model',
  'Last'
] as const

function csvCell(value: string): string {
  if (!/[",\n]/.test(value)) return value
  return `"${value.replace(/"/g, '""')}"`
}

/** One cell per table column, as the page words it: the swap column carries
 *  its denominator whenever a referee ruled. */
export function peerRowsToCsv(rows: readonly PeerTableRowView[]): string {
  const lines = [CSV_COLUMNS.join(',')]
  for (const row of rows) {
    const { swapped } = row.facts
    lines.push(
      [
        row.displayId,
        String(row.exchangeCount),
        row.facts.rewrote.text,
        row.facts.leftOut.text,
        swapped.checked > 0 ? `${swapped.text} (${swapped.tally})` : swapped.text,
        row.period
      ]
        .map(csvCell)
        .join(',')
    )
  }
  return `${lines.join('\n')}\n`
}

/** The evidence bundle -- the underlying Pane B rows and advertised-peer
 *  records themselves, not a re-shaping of the table. */
export function peerEvidenceBundle(dealtWith: readonly PaneBRow[], advertisedUnused: readonly Peer[]): string {
  return `${JSON.stringify(
    { schema: 'mesh-ledger-peers-evidence/1', dealt_with: dealtWith, advertised_unused: advertisedUnused },
    null,
    2
  )}\n`
}
