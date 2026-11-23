// Two-sided exchanges by week (Mesh-LLM/capsules-plugin#339): the Mesh-LLM
// checkpoint metric as one node can see it. "Both sides' records held" is the
// headline: an exchange whose other side's signed record this node holds,
// split into matching (confirmed) and differing; "confirmed" never means the
// headline (Sherlock2 on #339, answer 4). Every count carries its
// denominator, and nothing is added up across nodes: each node sees only its
// own records.
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'

/** How the page judged the other side's record of one exchange. */
export type OtherSide = 'matching' | 'differing' | 'not_held'

export type WeekCounts = {
  /** The week's Monday, `YYYY-MM-DD`, in UTC. */
  weekStart: string
  exchanges: number
  matching: number
  differing: number
}

/** The UTC Monday of `timestamp`, or `null` when it does not parse. */
export function weekStartOf(timestamp: string | null): string | null {
  if (!timestamp) return null
  const date = new Date(timestamp)
  if (Number.isNaN(date.getTime())) return null
  const day = date.getUTCDay() // 0 = Sunday
  const monday = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate() - ((day + 6) % 7)))
  return monday.toISOString().slice(0, 10)
}

/** Each week with an exchange, newest first, at most `limit` weeks. Rows
 *  with no readable time are left out and counted in `undated`. */
export function twoSidedWeeks(
  rows: readonly PaneCRow[],
  otherSide: (row: PaneCRow) => OtherSide,
  limit = 8
): { weeks: WeekCounts[]; undated: number } {
  const byWeek = new Map<string, WeekCounts>()
  let undated = 0
  for (const row of rows) {
    const weekStart = weekStartOf(row.timestamp)
    if (!weekStart) {
      undated += 1
      continue
    }
    const week = byWeek.get(weekStart) ?? { weekStart, exchanges: 0, matching: 0, differing: 0 }
    week.exchanges += 1
    const side = otherSide(row)
    if (side === 'matching') week.matching += 1
    else if (side === 'differing') week.differing += 1
    byWeek.set(weekStart, week)
  }
  const weeks = [...byWeek.values()].sort((a, b) => (a.weekStart < b.weekStart ? 1 : -1)).slice(0, limit)
  return { weeks, undated }
}

/** One week's line: the headline with its denominator, then the split. */
export function weekLine(week: WeekCounts): string {
  const held = week.matching + week.differing
  return `${held} of ${week.exchanges} with both sides' records held (${week.matching} matching, ${week.differing} differing)`
}

/** What the counts can and cannot show, beside the series. */
export const TWO_SIDED_NOTE =
  'Counts only the other side’s records this node holds. If either side has stopped sending its record, the count reads low.'
