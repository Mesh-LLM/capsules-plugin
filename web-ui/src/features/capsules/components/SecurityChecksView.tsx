// Toggle ② the security view (v3 §4) --
// renders INLINE under the row, keeping the two-sided columns, never a
// modal (v3 §4 "Where"). The headline carries the count and the legend once;
// the checks sit in four groups, one per question they answer, each opening
// on its own; the record itself (identity, header, what it commits to, and
// the raw bytes behind a readable/raw switch) is one click further.
import { CHECK_SOURCE_LEGEND, CHECK_SOURCE_WORDS } from '@/features/capsules/lib/tooltip-copy'
import { useEffect, useState, type ReactNode } from 'react'
import {
  buildCheckGroups,
  CHECK_MARK_GLYPH,
  countMarks,
  summarizeMarks,
  type CheckGroup,
  type CheckMark,
  type LineSide
} from '@/features/capsules/lib/check-groups'
import { Button } from '@/components/ui/button'
import { StatusBadge, type StatusBadgeTone } from '@/components/ui/StatusBadge'
import { cn } from '@/lib/cn'
import type { CapsuleRecord } from '@/features/capsules/api/types'
import type { ExchangeLedgerRow } from '@/features/capsules/lib/exchange-ledger'
import { checkRowDomId } from '@/features/capsules/lib/exchange-pages'
import type { PeerRecomputeState, RecomputedIdentity } from '@/features/capsules/lib/recompute-identity'
import { toneForState } from '@/features/capsules/lib/assurance-tone'
import {
  buildChecksRows,
  buildCommitsToRows,
  buildHeaderRows,
  buildIdentityRow,
  sharedTheirsDetail,
  theirsFetchable,
  type ChecksRow,
  type ChecksSideCell
} from '@/features/capsules/lib/security-checks-view'
import { ChipExplanationPopover } from '@/features/capsules/components/ChipExplanationPopover'
import { RECEIPT_PAGE_SENTENCE, SaveReceiptPage } from '@/features/capsules/components/SaveReceiptPage'

function badgeToneFor(state: string): StatusBadgeTone {
  const tone = toneForState(state)
  return tone === 'neutral' ? 'muted' : (tone as StatusBadgeTone)
}

function BlockHeading({ children }: { children: string }) {
  return (
    <p className="type-caption font-mono uppercase tracking-wide text-fg-faint" data-block-heading={children}>
      {children}
    </p>
  )
}

function TwoCol({ yours, theirs }: { yours: ReactNode; theirs: ReactNode | null }) {
  return (
    <div className="grid grid-cols-2 gap-x-3">
      <div className="min-w-0">{yours}</div>
      <div className="min-w-0">{theirs}</div>
    </div>
  )
}

function ChecksCell({
  cell,
  propertyKey,
  factKey,
  showDetail = true
}: {
  cell: ChecksSideCell
  propertyKey: string
  factKey?: 'binding'
  /** False when this sentence is already the column note (said once). */
  showDetail?: boolean
}) {
  // L-M: recomputed-here and taken-from-the-source must never render
  // identically -- distinct class + a distinct data attribute so a test can
  // assert the two classes differ, not just eyeball it.
  return (
    <p
      // No coloured bar (it read as a selection cursor); the source
      // is said in words beside any result.
      className={cn('flex items-baseline gap-1.5 text-xs', cell.recomputed ? 'text-foreground' : 'text-fg-dim')}
      data-detail={cell.detail}
      data-recomputed={cell.recomputed ? 'true' : 'false'}
      data-source={cell.recomputed ? 'recomputed-in-browser' : 'from-sidecar'}
    >
      {/* v3 §4: every chip opens the four-part explanation. p2 item 2
         (supersedes L-L's "inline, never on hover"): the chip stands
         alone; its sentence moves word for word into the chip's tooltip. */}
      <ChipExplanationPopover
        cell={cell}
        detail={showDetail ? cell.detail : undefined}
        factKey={factKey}
        propertyKey={propertyKey}
      >
        <StatusBadge size="caption" tone={badgeToneFor(cell.state)}>
          {cell.label}
        </StatusBadge>
      </ChipExplanationPopover>
      {cell.state === 'PASS' || cell.state === 'FAIL' ? (
        <span className="type-caption text-fg-faint" data-check-source-words="true">
          · {cell.recomputed ? CHECK_SOURCE_WORDS.here : CHECK_SOURCE_WORDS.node}
        </span>
      ) : null}
    </p>
  )
}

/** The CHECKS column header: blank · YOURS · THEIRS, with the repeated THEIRS
 *  sentence under it once. */
function ChecksColumnHeader({ theirsNote }: { theirsNote: string | null }) {
  return (
    <div className="grid grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)_minmax(0,1fr)] gap-x-3">
      <span />
      <p className="type-caption font-mono uppercase tracking-wide text-fg-faint">your record</p>
      <div>
        <p className="type-caption font-mono uppercase tracking-wide text-fg-faint">their record</p>
        {theirsNote ? (
          <p className="type-caption text-fg-faint" data-theirs-column-note="true">
            {theirsNote}
          </p>
        ) : null}
      </div>
    </div>
  )
}

/** One check: name -> your chip -> their chip (p2 item 2). */
function ChecksLine({
  id,
  name,
  mark,
  yours,
  theirs,
  highlighted
}: {
  id?: string
  name: string
  mark: CheckMark
  yours: ReactNode
  theirs: ReactNode
  highlighted: boolean
}) {
  return (
    <div
      className={cn(
        'grid grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)_minmax(0,1fr)] items-baseline gap-x-3 rounded',
        highlighted && 'ring-1 ring-accent/60 bg-accent/10'
      )}
      data-check-line={name}
      id={id}
    >
      <p className="type-caption text-fg-faint">
        <span aria-hidden="true" className="mr-1 font-mono" data-check-mark={mark}>
          {CHECK_MARK_GLYPH[mark]}
        </span>
        <span data-check-name="true">{name}</span>
      </p>
      <div className="min-w-0">{yours}</div>
      <div className="min-w-0">{theirs}</div>
    </div>
  )
}

const MARK_TONE: Record<CheckMark, StatusBadgeTone> = {
  here: 'good',
  node: 'muted',
  failed: 'bad',
  not_set_up: 'muted',
  none: 'muted'
}

/** A digest in the readable view: the first and last few characters, with
 *  the whole one a hover away. */
function shortDigest(value: string): string {
  return value.length > 16 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value
}

function SideView({
  side,
  theirsColumnNote
}: {
  side: LineSide | null
  /** The THEIRS sentence said once as the column note, left off its chips. */
  theirsColumnNote?: string | null
}) {
  if (!side) return <span className="text-xs text-fg-faint">—</span>
  if (side.kind === 'cell') {
    return (
      <ChecksCell
        cell={side.cell}
        factKey={side.factKey}
        propertyKey={side.propertyKey}
        showDetail={theirsColumnNote === undefined || side.cell.detail !== theirsColumnNote}
      />
    )
  }
  if (side.kind === 'digest') {
    return (
      <span className="inline-flex flex-wrap items-baseline gap-1.5">
        <span className="font-mono text-xs text-foreground" data-digest={side.value} title={side.value}>
          {shortDigest(side.value)}
        </span>
        {side.compared ? (
          <StatusBadge size="caption" tone={MARK_TONE[side.compared.mark]}>
            {side.compared.text}
          </StatusBadge>
        ) : null}
      </span>
    )
  }
  return (
    <StatusBadge size="caption" tone={MARK_TONE[side.mark]}>
      {side.text}
    </StatusBadge>
  )
}

function CheckGroupSection({
  group,
  open,
  onToggle,
  exchangeKey,
  highlightedPropertyKey,
  theirsColumnNote
}: {
  group: CheckGroup
  open: boolean
  onToggle: () => void
  exchangeKey: string
  highlightedPropertyKey: string | null
  theirsColumnNote: string | null
}) {
  const counts = countMarks(group.lines)
  return (
    <div className="flex flex-col gap-1.5 rounded border border-border-soft px-2 py-1.5" data-check-group={group.key}>
      <button
        aria-expanded={open}
        className="ui-control-ghost flex flex-wrap items-baseline justify-between gap-x-3 text-left"
        onClick={onToggle}
        type="button"
      >
        <span className="text-xs font-medium text-foreground">
          {open ? '▾' : '▸'} {group.question}
        </span>
        <span className="type-caption text-fg-faint" data-group-summary="true">
          {summarizeMarks(counts, false)}
        </span>
      </button>
      {open
        ? group.lines.map((line) => (
            <ChecksLine
              highlighted={line.propertyKey !== null && highlightedPropertyKey === line.propertyKey}
              id={line.propertyKey !== null ? checkRowDomId(exchangeKey, line.propertyKey) : undefined}
              key={line.id}
              mark={line.mark}
              name={line.name}
              theirs={<SideView side={line.theirs} theirsColumnNote={theirsColumnNote} />}
              yours={<SideView side={line.yours} />}
            />
          ))
        : null}
    </div>
  )
}

export type SecurityChecksViewProps = {
  row: ExchangeLedgerRow
  identity: RecomputedIdentity
  localRecord: CapsuleRecord | null
  /** Lifted to `ExchangeStreamRow` (mounted for every visible row, not just
   *  an expanded one) so a fetch this panel triggers can also flip that
   *  row's always-visible status badge once it resolves -- see
   *  `exchange-row-state.ts`'s `deriveRightCellState`. Optional only so a
   *  caller that hasn't wired a live fetch degrades to "not fetched" (never
   *  a fabricated match) -- `ExchangeStreamRow` always supplies a real one. */
  theirsRecompute?: PeerRecomputeState
  /** The property key the row's chip strip just jumped to -- rings the
   *  matching line, and opens the group it sits in so the jump lands.
   *  `null`/absent when no chip jump is pending. */
  highlightedPropertyKey?: string | null
  /** The row's check results, computed once by `ExchangeStreamRow` and
   *  shared with its chip strip so the two can never disagree (look finding
   *  1). Computed here only when a caller doesn't supply them. */
  checksRows?: readonly ChecksRow[]
  /** The other row of this row's twin pair, when the caller has it. */
  otherRow?: ExchangeLedgerRow | null
}

const NOT_FETCHED_DEFAULT: PeerRecomputeState = {
  status: 'not_fetched',
  idMatch: null,
  signatureOk: null,
  peerRecord: null,
  fetch: () => {}
}

export function SecurityChecksView({
  row,
  identity,
  localRecord,
  theirsRecompute = NOT_FETCHED_DEFAULT,
  highlightedPropertyKey = null,
  checksRows: suppliedChecksRows,
  otherRow = null
}: SecurityChecksViewProps) {
  const [rawMode, setRawMode] = useState(false)
  const [recordOpen, setRecordOpen] = useState(false)
  // Every group starts closed, except one holding a failed check: a failure
  // is never left behind a closed group. The reader's own toggle wins.
  const [chosen, setChosen] = useState<Readonly<Record<string, boolean>>>({})
  const canFetchTheirs = theirsFetchable(row.raw) !== null

  const identityRow = buildIdentityRow(row.raw, identity, theirsRecompute)
  const headerRows = buildHeaderRows(row.raw, localRecord, theirsRecompute)
  const commitsToRows = buildCommitsToRows(row.raw, localRecord, theirsRecompute)
  const checksRows = suppliedChecksRows ?? buildChecksRows(row.raw, identity, theirsRecompute)
  const theirsColumnNote = sharedTheirsDetail(checksRows)
  const groups = buildCheckGroups({ row: row.raw, otherRow: otherRow?.raw,
    counterparty: row.counterparty,
    otherCounterparty: otherRow?.counterparty,
    checks: checksRows, commits: commitsToRows })
  const headline = summarizeMarks(countMarks(groups.flatMap((group) => group.lines)), true)

  const isOpen = (group: CheckGroup) => chosen[group.key] ?? group.lines.some((line) => line.mark === 'failed')
  const openKeys = groups.filter(isOpen).map((group) => group.key).join(',')

  // A chip jump opens the group holding its line, then scrolls to it.
  useEffect(() => {
    if (!highlightedPropertyKey) return
    const group = groups.find((g) => g.lines.some((line) => line.propertyKey === highlightedPropertyKey))
    if (group) setChosen((prev) => (prev[group.key] ? prev : { ...prev, [group.key]: true }))
    // eslint-disable-next-line react-hooks/exhaustive-deps -- re-run only when the jump target changes
  }, [highlightedPropertyKey])
  useEffect(() => {
    if (!highlightedPropertyKey) return
    document
      .getElementById(checkRowDomId(row.exchangeKey, highlightedPropertyKey))
      ?.scrollIntoView?.({ block: 'nearest' })
    // eslint-disable-next-line react-hooks/exhaustive-deps -- scroll once the target's group is open
  }, [highlightedPropertyKey, openKeys])

  function toggleGroup(group: CheckGroup) {
    setChosen((prev) => ({ ...prev, [group.key]: !isOpen(group) }))
  }

  async function copyBoth() {
    const payload = JSON.stringify({ mine: row.raw.mine, theirs: row.raw.theirs }, null, 2)
    try {
      await navigator.clipboard.writeText(payload)
    } catch {
      // clipboard access denied/unavailable -- no crash, nothing else to do here.
    }
  }

  return (
    <div
      aria-label={`Security checks for ${row.exchangeKey}`}
      className="flex flex-col gap-3 rounded border border-border-soft bg-panel px-3 py-3"
      data-security-view="expanded"
      onClick={(event) => event.stopPropagation()}
      role="region"
    >
      {/* The headline: the count over its total, the legend said once, and
         the two columns' names. The row's own `▾ How we checked` toggle is
         this panel's only title. */}
      <div className="flex flex-col gap-1.5">
        <BlockHeading>checks</BlockHeading>
        <p className="text-xs text-foreground" data-checks-headline="true">
          {headline}
        </p>
        <p className="type-caption text-fg-faint" data-check-source-legend="true">
          {CHECK_SOURCE_LEGEND}
        </p>
        {/* Which record these checks are about, so a record an ask brought is
           never mistaken for the one the pane named. */}
        <p className="type-caption flex flex-wrap gap-x-3 text-fg-faint" data-record-ids="true">
          <span>
            your record <span className="font-mono text-foreground">{identityRow.yours.value}</span>
          </span>
          {identityRow.theirs ? (
            <span>
              their record <span className="font-mono text-foreground">{identityRow.theirs.value}</span>
            </span>
          ) : null}
        </p>
        {canFetchTheirs && theirsRecompute.status !== 'fetching' ? (
          // A real peer-asserted join key exists but this browser has not
          // fetched it yet -- an explicit action, never an automatic
          // background fetch (a mesh call is not a free local read). The
          // button never claims a verdict, just that this browser will go
          // look.
          <Button
            className="ui-control h-6 w-fit gap-1 px-2 text-[length:var(--density-type-caption)]"
            data-peer-fetch-action="mesh_ledger_fetch"
            onClick={() => theirsRecompute.fetch()}
            size="sm"
            type="button"
            variant="outline"
          >
            Get their record and check it here
          </Button>
        ) : null}
        <ChecksColumnHeader theirsNote={theirsColumnNote} />
      </div>

      <div className="flex flex-col gap-2">
        {groups.map((group) => (
          <CheckGroupSection
            exchangeKey={row.exchangeKey}
            group={group}
            highlightedPropertyKey={highlightedPropertyKey}
            key={group.key}
            onToggle={() => toggleGroup(group)}
            open={isOpen(group)}
            theirsColumnNote={theirsColumnNote}
          />
        ))}
      </div>

      <div className="flex flex-col gap-2 rounded border border-border-soft px-2 py-1.5" data-record-section="true">
        <button
          aria-expanded={recordOpen}
          className="ui-control-ghost text-left text-xs font-medium text-foreground"
          onClick={() => setRecordOpen((open) => !open)}
          type="button"
        >
          {recordOpen ? '▾' : '▸'} The record itself
        </button>
        {recordOpen ? (
          <>
            <div className="flex items-center justify-end gap-2">
              <div className="flex overflow-hidden rounded border border-border-soft" role="group">
                <Button
                  aria-pressed={!rawMode}
                  className="ui-control h-6 rounded-none px-2 text-[length:var(--density-type-caption)]"
                  onClick={() => setRawMode(false)}
                  size="sm"
                  type="button"
                  variant={rawMode ? 'ghost' : 'outline'}
                >
                  readable
                </Button>
                <Button
                  aria-pressed={rawMode}
                  className="ui-control h-6 rounded-none px-2 text-[length:var(--density-type-caption)]"
                  onClick={() => setRawMode(true)}
                  size="sm"
                  type="button"
                  variant={rawMode ? 'outline' : 'ghost'}
                >
                  raw
                </Button>
              </div>
              <Button
                className="ui-control h-6 gap-1 px-2 text-[length:var(--density-type-caption)]"
                onClick={copyBoth}
                size="sm"
                type="button"
                variant="outline"
              >
                ⧉ copy both
              </Button>
            </div>
            {rawMode ? (
              <pre className="max-h-64 overflow-auto rounded border border-border-soft bg-background p-2 font-mono text-xs text-fg-dim">
                {JSON.stringify({ mine: row.raw.mine, theirs: row.raw.theirs }, null, 2)}
              </pre>
            ) : (
              <>
                <div className="flex flex-col gap-1.5">
                  <BlockHeading>identity</BlockHeading>
                  <TwoCol
                    theirs={
                      identityRow.theirs ? (
                        <p className="font-mono text-xs text-foreground">
                          {identityRow.theirs.value}
                          <span className="block text-fg-faint">{identityRow.theirs.note}</span>
                        </p>
                      ) : null
                    }
                    yours={
                      <p className="font-mono text-xs text-foreground">
                        {identityRow.yours.value}
                        <span className="block text-fg-faint">{identityRow.yours.note}</span>
                      </p>
                    }
                  />
                </div>

                <div className="flex flex-col gap-1.5">
                  <BlockHeading>header</BlockHeading>
                  {headerRows.map((headerRow) => (
                    <div className="flex flex-col gap-0.5" key={headerRow.label}>
                      <p className="type-caption text-fg-faint">{headerRow.label}</p>
                      <TwoCol
                        theirs={
                          headerRow.theirs ? (
                            <p className="text-xs text-foreground">
                              {headerRow.theirs.value}
                              {headerRow.theirs.note ? (
                                <span className="ml-1 text-fg-faint">{headerRow.theirs.note}</span>
                              ) : null}
                            </p>
                          ) : null
                        }
                        yours={<p className="text-xs text-foreground">{headerRow.yours.value}</p>}
                      />
                    </div>
                  ))}
                </div>

                <div className="flex flex-col gap-1.5">
                  <BlockHeading>what it commits to</BlockHeading>
                  {commitsToRows.map((commitsRow) => (
                    <div className="flex flex-col gap-0.5" key={commitsRow.label}>
                      <p className="type-caption text-fg-faint">{commitsRow.label}</p>
                      <TwoCol
                        theirs={
                          commitsRow.theirs ? (
                            <p className="truncate font-mono text-xs text-foreground">
                              {commitsRow.theirs.value}
                              <span className="ml-1 text-fg-faint">{commitsRow.theirs.note}</span>
                            </p>
                          ) : null
                        }
                        yours={<p className="truncate font-mono text-xs text-foreground">{commitsRow.yours}</p>}
                      />
                    </div>
                  ))}
                </div>
              </>
            )}
          </>
        ) : null}
      </div>

      {/* "Save receipt page": this exchange's receipt as a page for an outside
         party, checking itself when it opens (Steven's 10-29 ruling, item 1;
         `SaveReceiptPage.tsx`). It stays on every row: a row with no paid
         deal saves the page that says so. */}
      <div className="flex flex-col gap-1.5 border-t border-border-soft pt-2">
        <SaveReceiptPage exchangeKey={row.exchangeKey} row={row.raw} />
        <p className="text-xs text-fg-faint">{RECEIPT_PAGE_SENTENCE}</p>
      </div>
    </div>
  )
}

