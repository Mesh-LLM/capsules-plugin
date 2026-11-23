// Two-sided exchanges by week (Mesh-LLM/capsules-plugin#339): the Mesh-LLM
// checkpoint metric as one node can see it. "Both sides' records held" is the
// headline: an exchange whose other side's signed record this node holds,
// split into matching (confirmed) and differing; "confirmed" never means the
// headline (Sherlock2 on #339, answer 4). Every count carries its
// denominator, and nothing is added up across nodes: each node sees only its
// own records.
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'
import { fullTimeInstant } from '@/features/capsules/lib/exchange-row-state'

/** How the page judged the other side's record of one exchange. */
export type OtherSide = 'matching' | 'differing' | 'not_held'

export type WeekCounts = {
  /** The week's Monday, `YYYY-MM-DD`, in UTC. */
  weekStart: string
  exchanges: number
  matching: number
  differing: number
}

/** The UTC Monday of `timestamp`, or `null` unless it is a full RFC 3339
 *  time with a zone (`fullTimeInstant`): a zone-less time names no one
 *  instant, so no one week. */
export function weekStartOf(timestamp: string | null): string | null {
  const at = fullTimeInstant(timestamp)
  if (at === null) return null
  const date = new Date(at)
  const day = date.getUTCDay() // 0 = Sunday
  const monday = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate() - ((day + 6) % 7)))
  return monday.toISOString().slice(0, 10)
}

/** Exchanges with their other side's records counted, outside any listed
 *  week. */
export type Rest = { exchanges: number; matching: number; differing: number }

/** Each week with an exchange, newest first, at most `limit` weeks. Rows
 *  with no readable time are counted in `undated`, and weeks past the limit
 *  in `earlier` (with `earlierWeeks`), each with its own split, so the page
 *  can say what it does not list and every count still adds up to the
 *  tiles. */
export function twoSidedWeeks(
  rows: readonly PaneCRow[],
  otherSide: (row: PaneCRow) => OtherSide,
  limit = 8
): { weeks: WeekCounts[]; undated: Rest; earlier: Rest; earlierWeeks: number } {
  const byWeek = new Map<string, WeekCounts>()
  const undated: Rest = { exchanges: 0, matching: 0, differing: 0 }
  const add = (counts: Rest, row: PaneCRow) => {
    counts.exchanges += 1
    const side = otherSide(row)
    if (side === 'matching') counts.matching += 1
    else if (side === 'differing') counts.differing += 1
  }
  for (const row of rows) {
    const weekStart = weekStartOf(row.timestamp)
    if (!weekStart) {
      add(undated, row)
      continue
    }
    const week = byWeek.get(weekStart) ?? { weekStart, exchanges: 0, matching: 0, differing: 0 }
    add(week, row)
    byWeek.set(weekStart, week)
  }
  const all = [...byWeek.values()].sort((a, b) => (a.weekStart < b.weekStart ? 1 : -1))
  const older = all.slice(limit)
  const earlier = older.reduce<Rest>(
    (sum, w) => ({
      exchanges: sum.exchanges + w.exchanges,
      matching: sum.matching + w.matching,
      differing: sum.differing + w.differing
    }),
    { exchanges: 0, matching: 0, differing: 0 }
  )
  return { weeks: all.slice(0, limit), undated, earlier, earlierWeeks: older.length }
}

/** A count's line: the headline with its denominator, then the split. */
export function weekLine(week: Rest): string {
  const held = week.matching + week.differing
  return `${held} of ${week.exchanges} with both sides' records held (${week.matching} matching, ${week.differing} differing)`
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`

/** The line for exchanges with no readable time. */
export function undatedLine(rest: Rest): string {
  return `${plural(rest.exchanges, 'exchange has', 'exchanges have')} no time, so no week: ${weekLine(rest)}.`
}

/** The line for weeks past the listed ones. */
export function earlierLine(weeks: number, rest: Rest): string {
  return `${plural(weeks, 'earlier week', 'earlier weeks')}, not listed: ${weekLine(rest)}.`
}

/** What the counts can and cannot show, beside the series. */
export const TWO_SIDED_NOTE =
  'Weeks start Monday, UTC. Counts only the other side’s records this node holds: if the other side stops sending its record, or this node’s “Send your record to the other side” is off, the count reads low.'
