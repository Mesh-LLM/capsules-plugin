// The Evidence page's one clock (Sherlock2's ruling on #408): the live page
// shows the viewer's own time zone and names it on every printed time, and
// groups rows by the calendar day in that same zone. `timeZone` is left out
// in the page (the viewer's zone); tests pass one so they read the same on
// any machine. The saved receipt is capsule-viewer's and stays in UTC.

const FORMATS = new Map<string, Intl.DateTimeFormat>()

/** The row face's short time, or (`full`) the table's: year and seconds too,
 *  so two records in one minute or in different years stay apart. */
function timeFormat(timeZone: string | undefined, full: boolean): Intl.DateTimeFormat {
  const key = `${full ? 'full' : 'short'}:${timeZone ?? ''}`
  let format = FORMATS.get(key)
  if (!format) {
    // The viewer's locale, as before (the way Chat shows it).
    format = new Intl.DateTimeFormat(undefined, {
      ...(full ? { year: 'numeric', second: '2-digit' } : {}),
      month: 'short',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
      timeZoneName: 'short',
      timeZone
    })
    FORMATS.set(key, format)
  }
  return format
}

/** "Nov 27, 8:21 PM CST": the viewer's own time zone, named. */
export function formatExchangeTimestamp(timestamp: string | null, timeZone?: string): string {
  if (!timestamp) return 'timestamp unavailable'
  const date = new Date(timestamp)
  return Number.isNaN(date.getTime()) ? timestamp : timeFormat(timeZone, false).format(date)
}

/** "Nov 27, 2026, 8:21:22 PM CST": the table view's time, with year and
 *  seconds, in the viewer's zone, named. */
export function formatExchangeTimestampFull(timestamp: string | null, timeZone?: string): string {
  if (!timestamp) return 'timestamp unavailable'
  const date = new Date(timestamp)
  return Number.isNaN(date.getTime()) ? timestamp : timeFormat(timeZone, true).format(date)
}

/** The calendar day `date` falls on in `timeZone` (the viewer's when left
 *  out), as `YYYY-MM-DD`. */
export function localDayKey(date: Date, timeZone?: string): string {
  const parts = new Intl.DateTimeFormat('en-US', { year: 'numeric', month: '2-digit', day: '2-digit', timeZone })
    .formatToParts(date)
  const part = (type: string) => parts.find((p) => p.type === type)?.value ?? ''
  return `${part('year')}-${part('month')}-${part('day')}`
}

const MONTH_ABBR = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'] as const

/** The local calendar day of an ISO time (`null` when unparseable), for
 *  date-only labels that must agree with the day headers. */
export function localDateParts(
  isoTimestamp: string,
  timeZone?: string
): { day: number; month: string; year: number } | null {
  const date = new Date(isoTimestamp)
  if (Number.isNaN(date.getTime())) return null
  const [year, month, day] = localDayKey(date, timeZone).split('-').map(Number)
  return { day, month: MONTH_ABBR[month - 1], year }
}

/** "Nov 28, 2026, 02:21 UTC": a saved page's time, which stays in UTC with
 *  the zone said, to the minute, in capsule-viewer's R6 words form
 *  (docs/design/receipt-presentation.md; Sherlock2's correction f55ef9b5:
 *  never ":00", records keep the time to the minute). */
export function formatUtcTimestamp(timestamp: string): string {
  const date = new Date(timestamp)
  if (Number.isNaN(date.getTime())) return timestamp
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${MONTH_ABBR[date.getUTCMonth()]} ${date.getUTCDate()}, ${date.getUTCFullYear()}, ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())} UTC`
}
