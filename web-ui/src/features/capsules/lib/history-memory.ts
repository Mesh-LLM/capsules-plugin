// The last verified "Ask for their history" result per peer, kept in this
// browser so a reload still shows it, with when it was checked. Only a
// verified result is kept: a failure or a refusal says nothing worth carrying
// over. This is a per-viewer convenience, not a record: the node holds no
// copy, every read and write is wrapped (storage can be blocked or absent),
// and the page works the same without it.
//
// Each entry keeps its witness standing. An entry stored before the standing
// was kept has none, and is restored as `not_recorded`: never as witnessed,
// and never as checked against no witness, since neither was recorded.
import type { HistoryOutcome } from '@/features/capsules/lib/ask-for-history'
import type { WitnessStanding } from '@/features/capsules/lib/ask-for-record'

export const HISTORY_MEMORY_KEY = 'capsules.evidence.verified-history.v1'

export type VerifiedHistory = Extract<HistoryOutcome, { kind: 'verified' }>

function isVerifiedHistory(value: unknown): value is VerifiedHistory {
  if (!value || typeof value !== 'object') return false
  const v = value as Record<string, unknown>
  return (
    v.kind === 'verified' &&
    typeof v.at === 'string' &&
    (v.checkpoints === null || (typeof v.checkpoints === 'number' && Number.isInteger(v.checkpoints)))
  )
}

const STANDINGS: readonly WitnessStanding[] = ['witnessed', 'unwitnessed', 'no_witness', 'not_recorded']

function storedStanding(value: unknown): WitnessStanding {
  return STANDINGS.find((s) => s === value) ?? 'not_recorded'
}

/** Peer id -> its last verified history. Anything unreadable is skipped. */
export function loadVerifiedHistories(): Map<string, VerifiedHistory> {
  const out = new Map<string, VerifiedHistory>()
  try {
    const parsed: unknown = JSON.parse(window.localStorage.getItem(HISTORY_MEMORY_KEY) ?? '{}')
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return out
    for (const [peerId, entry] of Object.entries(parsed)) {
      if (isVerifiedHistory(entry)) out.set(peerId, {
          kind: 'verified',
          at: entry.at,
          checkpoints: entry.checkpoints,
          witness: storedStanding((entry as Record<string, unknown>).witness),
          ...((entry as Record<string, unknown>).sampled === true ? { sampled: true as const } : {})
        })
    }
  } catch {
    // No storage, or nothing readable in it: nothing remembered.
  }
  return out
}

/** Remember `outcome` for `peerId` when it is verified; returns the updated
 *  map either way, so the page shows it even when storage can't keep it. */
export function rememberVerifiedHistory(
  current: ReadonlyMap<string, VerifiedHistory>,
  peerId: string,
  outcome: HistoryOutcome
): ReadonlyMap<string, VerifiedHistory> {
  if (outcome.kind !== 'verified') return current
  const next = new Map(current).set(peerId, outcome)
  try {
    window.localStorage.setItem(HISTORY_MEMORY_KEY, JSON.stringify(Object.fromEntries(next)))
  } catch {
    // Storage full or blocked: kept for this visit only.
  }
  return next
}

/** Which row shows a peer's remembered history: a history is a fact about
 *  the peer, not about any one exchange, so it is said once, on that peer's
 *  newest row. Peer id -> that row's key; a row with no time loses to one
 *  with a time, and ties keep the first row seen. */
export function newestRowPerPeer(
  rows: readonly { key: string; peerId: string | null; timestamp: string | null }[]
): Map<string, string> {
  const newest = new Map<string, { key: string; at: number }>()
  for (const row of rows) {
    if (!row.peerId) continue
    const parsed = row.timestamp ? Date.parse(row.timestamp) : Number.NaN
    const at = Number.isNaN(parsed) ? Number.NEGATIVE_INFINITY : parsed
    const current = newest.get(row.peerId)
    if (!current || at > current.at) newest.set(row.peerId, { key: row.key, at })
  }
  return new Map([...newest].map(([peerId, { key }]) => [peerId, key]))
}
