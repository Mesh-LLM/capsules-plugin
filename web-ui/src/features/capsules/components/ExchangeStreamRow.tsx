// One row of the two-sided Ledger stream.
// v3 §2's anatomy: a role marker (`●` asked / `◐` served -- no rail, L-O), a
// left session rail when this row and the previous one share a session
// (L-N), and the two-sided record itself -- `YOUR RECORD │ THEIR RECORD, AS
// GIVEN TO YOU`. The column labels themselves now live in the sticky header
// above the stream (v3 §2a), not repeated per row.
// v3 §2/§3/§4 -- the row carries its own two
// explicit toggles, `▸/▾ content` and `▸/▾ checks`, right below the summary
// row. There is no modal and no whole-row click target: the two toggles are
// the entire detail surface.
import { useEffect, useRef, useState } from 'react'
import { Button } from '@/components/ui/button'
import { StatusBadge, type StatusBadgeTone } from '@/components/ui/StatusBadge'
import { cn } from '@/lib/cn'
import type { CapsuleRecord } from '@/features/capsules/api/types'
import { SeeInLogsLink } from '@/features/capsules/components/ExchangeIdCell'
import { AgreementStrip } from '@/features/capsules/components/AgreementStrip'
import { ExchangeRowChips } from '@/features/capsules/components/ExchangeRowChips'
import { ReceiptPanel } from '@/features/capsules/components/ReceiptPanel'
import { SecurityChecksView } from '@/features/capsules/components/SecurityChecksView'
import {
  ProviderSettlementStrip,
  SettlementEntries,
  SettlementStrip
} from '@/features/capsules/components/SettlementRow'
import { buildChecksRows } from '@/features/capsules/lib/security-checks-view'
import { theirContentText, yourContentFixedText } from '@/features/capsules/lib/exchange-content-state'
import { isServedForPay, type ExchangeLedgerRow } from '@/features/capsules/lib/exchange-ledger'
import {
  NOT_ON_MESH,
  askTarget,
  otherSideNodeId,
  rowAskControls,
  type AskTarget,
  type RowAsk,
  type RowAskControl
} from '@/features/capsules/lib/ask-for-record'
import { judgeRow } from '@/features/capsules/lib/row-evidence'
import { historyNote, type HistoryOutcome } from '@/features/capsules/lib/ask-for-history'
import { HoverChip } from '@/features/capsules/components/HoverChip'
import { entryRowChipMark, entryRowChipPropertyKey } from '@/features/capsules/lib/entry-row-chips'
import { checkRowDomId, exchangeRowDomId } from '@/features/capsules/lib/exchange-pages'
import {
  bracketStrip,
  bracketStripText,
  closedPropertyCellItems,
  isAlarmState,
  isAskAction,
  rightCellAction,
  rightCellDetail,
  type RightCellStateKind,
  rightCellStatusLabel,
  rightCellText,
  rowStatusLabel
} from '@/features/capsules/lib/exchange-row-state'
import { InfoHover } from '@/features/capsules/components/InfoHover'
import type { RailSegment } from '@/features/capsules/lib/exchange-stream'
import { usePeerLedgerRecompute, useRecomputedIdentity } from '@/features/capsules/lib/recompute-identity'
import {
  durationText,
  pocBlock,
  rowModelName,
  servingProvenance,
  tokenFlowText
} from '@/features/capsules/lib/serving-provenance'
import { shortId } from '@/features/capsules/lib/short-id'
import { StageStrip } from '@/features/capsules/components/StageStrip'
import { copyStateLabel } from '@/lib/copyStateLabel'
import { useClipboardCopy } from '@/lib/useClipboardCopy'
import { formatExchangeTimestamp } from '@/features/capsules/lib/local-time'
import { RowVerdictLine } from '@/features/capsules/components/RowVerdictLine'
import { rowCombinationText } from '@/features/capsules/lib/row-combination'
import { NO_PEER_NAMES, peerName as namePeer, resolveRowPeer } from '@/features/capsules/lib/peer-names'
import { isWaitingForTheirRecord, rowSteps, rowVerdictText, type RowStep } from '@/features/capsules/lib/row-verdict'
import {
  CONFIRMED_NOT_KEPT,
  FAILED_TOOLTIP,
  LOCAL_ONLY_TOOLTIP,
  OWN_RECORD_FAILS_WARNING,
  SAVED_BECAUSE_YOU_ASKED,
  SERVED_FOR_PAY_NO_PAYER_TOOLTIP
} from '@/features/capsules/lib/tooltip-copy'

/** The gated cell text (Do (2)) when an ask
 *  action's row carries no recorded counterparty. This splits by which of two
 *  distinct truths holds -- the old single "nothing to ask yet" implied a
 *  future action the reader can't take and hid which situation they were in:
 *   - a SERVED row: this node served locally, there is no remote counterparty
 *     on the other side to ask at all -> `Local — no other side`;
 *   - a SERVED row this node served for pay: another node paid for it, but
 *     its id is not recorded -> `Served for pay — payer not recorded`;
 *   - an ASKED row: a remote exchange happened but the peer is unknown/
 *     unrecorded (no counterparty identity field exists on the record yet; the
 *     join comes from Pane B, per-peer) -> `Other side: not known`.
 *  Each is a stated fact, never a deficit or a "not yet". */
const NO_OTHER_SIDE_TEXT = 'Local — no other side'
/** The badge on a served exchange with no other side anywhere. */
const NO_OTHER_SIDE_LABEL = 'No other side'
const FAILED_LABEL = 'Failed'
const FAILED_FACE_TEXT = 'The exchange failed'
const OTHER_SIDE_NOT_KNOWN_TEXT = 'Other side: not known'
const PAYER_NOT_RECORDED_TEXT = 'Served for pay — payer not recorded'

function roleText(roleTag: string): string {
  // `You served`/`You asked` are stated in words on every row -- never
  // inferred from position or colour alone (v3 §2).
  if (roleTag === 'FAILED') return 'Exchange failed'
  return roleTag === 'SERVED' ? 'You served' : 'You asked'
}

/** Design §3A: "one colour per state ... taken from the console palette,
 *  nowhere else." CLOSED gets the Logs card's COMPLETED green, CONTRADICTED
 *  its FAILED red, refused/absent the `Local only` amber -- every other OPEN
 *  variant stays muted/no colour (L-A: "an open row is never styled as a
 *  problem"). Distinct from `isAlarmState`, which only gates the dot. */
function rowStateTone(kind: RightCellStateKind): StatusBadgeTone {
  switch (kind) {
    case 'closed':
      return 'good'
    case 'contradicted':
      return 'bad'
    case 'open_refused':
    case 'open_absent':
      return 'warn'
    default:
      return 'muted'
  }
}

const ROW_BUTTON_CLASS =
  'ui-control h-7 w-fit gap-1 rounded-[var(--radius)] px-2 text-[length:var(--density-type-caption)]'

/** One of the row's two asks: a live button, or a disabled one that says on
 *  hover (and to screen readers) why it can't be sent. */
function AskButton({ control, onAsk, census }: { control: RowAskControl; onAsk: () => void; census: string }) {
  const button = (
    <Button
      className={ROW_BUTTON_CLASS}
      disabled={control.disabledReason !== null}
      onClick={onAsk}
      size="sm"
      type="button"
      variant="outline"
    >
      {control.label}
    </Button>
  )
  if (control.disabledReason === null) return button
  // A disabled button gets no pointer events, so the wrapper takes the hover.
  return (
    <HoverChip census={census} label={control.disabledReason}>
      <span className="inline-flex">{button}</span>
    </HoverChip>
  )
}

/** `Sealed → In a checkpoint → Confirmed by them`: the row's progress in
 *  three plain steps, a step not reached greyed. The per-check chips live in
 *  "How we checked". */
function RowSteps({ steps }: { steps: readonly RowStep[] }) {
  return (
    <ol aria-label="steps" className="flex flex-wrap items-center gap-1.5 text-xs" data-row-steps="true">
      {steps.map((step, index) => (
        <li
          className={cn('inline-flex items-center gap-1.5', step.reached ? 'text-foreground' : 'text-fg-faint')}
          data-reached={step.reached ? 'true' : 'false'}
          data-step={step.key}
          key={step.key}
        >
          {index > 0 ? (
            <span aria-hidden="true" className="text-fg-faint">
              →
            </span>
          ) : null}
          <span>{step.label}</span>
        </li>
      ))}
    </ol>
  )
}

/** A whole sentence: a note that ends without a stop gets one. */
function sentence(text: string): string {
  return /[.!?]$/.test(text) ? text : `${text}.`
}

/** A short/copyable identifier (design §3A) -- `role="link"`, not `button`, for the same reason
 *  `ExchangeRowChips` isn't: this jumps/copies rather than performing a row
 *  action, so it doesn't inflate the row's `getAllByRole('button')` count.
 *  Copy state via `useClipboardCopy` (`CopyInstructionRow`'s own hook) --
 *  never a second, hand-rolled clipboard try/catch. */
function CopyableId({ label, value }: { label: string; value: string }) {
  const { copyState, copyText } = useClipboardCopy()
  function copy() {
    void copyText(value)
  }
  return (
    <span className="inline-flex items-center gap-1">
      <span className="text-fg-faint">{label}</span>
      <span
        aria-label={`${copyStateLabel(copyState)} ${label} id ${value}`}
        className="ui-control-ghost cursor-pointer text-foreground"
        onClick={copy}
        onKeyDown={(event) => {
          if (event.key !== 'Enter' && event.key !== ' ') return
          event.preventDefault()
          copy()
        }}
        role="link"
        tabIndex={0}
        title={value}
      >
        {shortId(value)}
      </span>
      {copyState === 'copied' ? <span className="text-fg-faint">copied</span> : null}
    </span>
  )
}

export type ExchangeStreamRowProps = {
  row: ExchangeLedgerRow
  rail: RailSegment
  /** Keyboard nav cursor (j/k) -- transient, not persisted anywhere. */
  focused?: boolean
  /** The per-row deep-link target (v3 §2a "opening its page with the row
   *  expanded and highlighted") -- persists until a different row is
   *  focused via deep link, independent of keyboard focus. */
  highlighted?: boolean
  /** `c` keyboard toggle -- reveals this row's Checks column value inline.
   *  Real per-row Checks toggle ② (v3 §4) is a later batch; this is the
   *  honest minimum today's data already supports (`checksText`, the same
   *  field the CSV export already uses). */
  checksExpanded?: boolean
  /** `o` keyboard toggle -- reveals this row's content cells inline
   *  (v3 §3): one populated side, one
   *  empty side, flipping with `Your role` (L-F). */
  contentExpanded?: boolean
  /** This row's own local capsule record --
   *  needed to recompute `content_binding`/`producer_signature` in-browser
   *  for the security view. `null` when the record hasn't been fetched
   *  (never a stand-in for a trusted result). */
  localRecord?: CapsuleRecord | null
  nodePubKeyPem?: string | null
  /** Whether the latest checkpoint covers this row's own record (look
   *  finding 2, `checkpointCoverageByRecord`); `null` = not reported. */
  checkpointCovered?: boolean | null
  /** p2 item 3: this node's owner link (`ownerLinked`, the same derivation
   *  Integrity's step 2 reads); `null` = not known. */
  ownerLinked?: boolean | null
  /** Toggle ① -- flips `contentExpanded` for this row (the `▸/▾ content` control). */
  onToggleContent: (row: ExchangeLedgerRow) => void
  /** Toggle ② -- flips `checksExpanded` for this row (the `▸/▾ checks` control). */
  onToggleChecks: (row: ExchangeLedgerRow) => void
  /** What "Ask for their record" produced for this row, if it asked:
   *  the latest reply and the latest verified one (`settleRowAsk`). */
  askOutcome?: RowAsk | null
  /** Sends the ask. Absent where the page can't ask (a saved sample): the
   *  button stays, disabled, saying why. */
  onAskForRecord?: (row: ExchangeLedgerRow, target: AskTarget) => void
  /** What "Ask for their history" produced for this row, if it asked. */
  historyOutcome?: HistoryOutcome | null
  /** Sends the history ask to the other side's node. Absent as above. */
  onAskForHistory?: (row: ExchangeLedgerRow, peerId: string) => void
  /** How the page names a peer (`peer-names.ts` `usePeerNames`): hostname,
   *  then short id. Defaults to the short id alone. */
  peerName?: (id: string) => string
  /** No witness is set on this node: no "witnessed" chip in the checks. */
  witnessOff?: boolean
  /** The node Pane B joins to this row's `key:` counterparty
   *  (`identity.node_id`), when it knows one (`resolveRowPeer`). */
  counterpartyNodeId?: string | null
  /** The other row of this row's twin pair, when the page has it. */
  otherRow?: ExchangeLedgerRow | null
}

const shortIdOnly = (id: string) => namePeer(id, NO_PEER_NAMES)

export function ExchangeStreamRow({
  row,
  rail,
  focused = false,
  highlighted = false,
  checksExpanded = false,
  contentExpanded = false,
  localRecord = null,
  nodePubKeyPem = null,
  checkpointCovered = null,
  ownerLinked = null,
  onToggleContent,
  onToggleChecks,
  askOutcome = null,
  onAskForRecord,
  historyOutcome = null,
  onAskForHistory,
  peerName = shortIdOnly,
  witnessOff = false,
  counterpartyNodeId = null,
  otherRow = null
}: ExchangeStreamRowProps) {
  // Lifted here (not `SecurityChecksView`, which only mounts once `▸
  // checks` is expanded) so a fetch this hook's `.fetch()` triggers can
  // also flip this row's ALWAYS-VISIBLE status badge the moment it
  // resolves, not just the expanded panel's own cells
  // (finding 1). The hook
  // itself is cheap and a no-op until `.fetch()` is called (rules of
  // hooks require it run unconditionally, same as `useRecomputedIdentity`
  // below).
  // A live fetch wins when this browser ran one; otherwise the pushed half the
  // pane already correlated (its capsule_id recomputed before the query
  // resolved). Either way the SAME gate below judges it, and the checks panel
  // shows the same evidence.
  // Every source of their record, their claims and our asks, weighed by the
  // rules in `row-evidence.ts`: the ONE record chosen feeds the state, the
  // checks panel and Compare alike.
  const peerFetch = usePeerLedgerRecompute(row.raw)
  const judged = judgeRow(row.raw, localRecord, peerFetch, askOutcome)
  // "Get their record and check it here" always runs the live fetch, whichever
  // record is shown (a pushed or asked one carries no fetch of its own).
  const theirsRecompute = judged.evidence ? { ...judged.evidence, fetch: peerFetch.fetch } : peerFetch
  const state = judged.state
  const askNote = judged.askNote
  const retryNote = judged.retryNote
  const alarm = isAlarmState(state)
  // Whom to ask, and how to name the exchange, from our own record of it.
  const askFor = askTarget(localRecord ?? (row.raw.mine.record as CapsuleRecord | undefined) ?? null)
  const askPeer = otherSideNodeId(localRecord ?? (row.raw.mine.record as CapsuleRecord | undefined) ?? null)
  const historyLine = historyOutcome ? historyNote(historyOutcome) : null
  // Do (2): a row waiting on a counterparty it has no record of says so in
  // the cell, branching on WHICH truth holds -- a SERVED row has no remote other side to ask; an ASKED row
  // has one, but it's unknown/unrecorded. Never a single "nothing to ask yet"
  // that hides the difference.
  const gatedByCounterparty = isAskAction(state.kind) && !row.counterparty && !askFor
  // A served exchange with no other side anywhere: LOCAL, not OPEN, since
  // nothing of theirs can arrive (`isLocalOnly`). An ask this row sent would
  // name another side, so it ends this.
  const localOnly = row.localOnly && !askOutcome
  const servedForPay = isServedForPay(row.raw)
  const gatedText =
    row.roleTag !== 'SERVED' ? OTHER_SIDE_NOT_KNOWN_TEXT : servedForPay ? PAYER_NOT_RECORDED_TEXT : NO_OTHER_SIDE_TEXT
  const cellText = gatedByCounterparty ? gatedText : rightCellText(state)
  // The face says the verdict in plain words, naming the other node; the
  // longer sentences (the state's own, and what an ask returned and how it
  // was checked) move behind its (i).
  // One node, named once: the event line and the verdict say the same.
  const otherSide = resolveRowPeer({
    askPeer,
    counterparty: row.counterparty,
    receivedFrom: row.raw.theirs.received_from ?? null,
    keyNodeId: counterpartyNodeId
  })
  const otherSideName = otherSide ? peerName(otherSide) : null
  // An ask that couldn't reach the node (it left the mesh) is said on the
  // face, not only behind the (i).
  const latestAsk = askOutcome?.latest ?? null
  const notOnMesh = latestAsk?.kind === 'no_reply' && latestAsk.plain === true && latestAsk.detail === NOT_ON_MESH
  const failed = row.roleTag === 'FAILED'
  const faceText = failed
    ? FAILED_FACE_TEXT
    : gatedByCounterparty
      ? gatedText
      : rowVerdictText(state, otherSideName, notOnMesh)
  // A confirmation from the record the node holds because this node asked
  // for it (the pane's `via: "ask"`; a pushed one is `"push"`) says so.
  // One the ask brought but the plugin couldn't save says that instead.
  const savedByAsk = judged.confirmedUnsaved
    ? CONFIRMED_NOT_KEPT
    : state.kind === 'closed' && row.raw.theirs.via === 'ask'
      ? SAVED_BECAUSE_YOU_ASKED
      : null
  // Nothing the face already says is repeated behind the (i).
  // Their signed refusal, when an ask brought it, says the decline with its
  // time and reason; the state's own "They declined…" would say it twice.
  const refusalFromAsk = state.kind === 'open_refused' && askNote !== null
  const verdictDetail = [refusalFromAsk ? null : cellText, savedByAsk, askNote ? askNote.text : null, retryNote]
    .filter((text): text is string => text !== null)
    .map(sentence)
    .filter((text) => text !== sentence(faceText))
    .join(' ')
  // The row's two asks, always on the row face: record push may be off
  // on their node, so asking is how their record (or their history) gets here. Each
  // is live as soon as our record names the other side's node, and otherwise
  // says why not.
  const asks = rowAskControls({
    kind: state.kind,
    target: askFor,
    peerId: askPeer,
    canAsk: onAskForRecord !== undefined && onAskForHistory !== undefined,
    roleTag: row.roleTag,
    servedForPay,
    otherSideKnown: row.counterparty !== null,
    recordAsk: askOutcome?.latest ?? null,
    historyAsk: historyOutcome
  })
  const action = rightCellAction(state)
  // Look finding 1: the chip strip on the collapsed row must show the same
  // results as the panel, so this node's own record is recomputed for every
  // rendered row, not only an expanded one. It is a local hash + signature
  // verify over bytes already in the browser -- no fetch.
  const identity = useRecomputedIdentity(localRecord, nodePubKeyPem)
  // ONE set of check results for both the strip and the panel; the gate's
  // verdict feeds the outcome row so the badge, strip and panel agree.
  const checksRows = buildChecksRows(row.raw, identity, theirsRecompute, {
    gateKind: state.kind,
    checkpointCovered,
    ownerLinked
  })
  // Your own copy failed "words match" or "signed". Whatever
  // the badge says (Confirmed included), the row says so.
  const ownRecordFails = entryRowChipMark(checksRows, 'content') === '✗' || entryRowChipMark(checksRows, 'sig') === '✗'
  // The bracket strip, drawn in words (UX §3): `Yours ● sealed —— Theirs ●
  // same`. Same state the badge renders.
  const bracket = bracketStrip(row.raw, state)
  const strip = bracketStripText(localOnly ? { ...bracket, theirs: { glyph: '○', word: 'no other side' } } : bracket)
  // One hover on the strip for what the badge and the chips say together.
  const combination = rowCombinationText({
    state: state.kind,
    roleTag: row.roleTag,
    servedForPay,
    yoursHeld: row.raw.mine.state !== 'absent',
    marks: {
      content: entryRowChipMark(checksRows, 'content'),
      sig: entryRowChipMark(checksRows, 'sig'),
      inclusion: entryRowChipMark(checksRows, 'inclusion', checkpointCovered),
      registered: entryRowChipMark(checksRows, 'registered')
    },
    refusedAtTheDoor: row.raw.theirs.evidence_outcome === 'claims_refused',
    askPeer: askPeer ? otherSideName : null
  })
  const steps = rowSteps({
    sealed: row.raw.mine.state !== 'absent',
    inCheckpoint: ['✓', '◐'].includes(entryRowChipMark(checksRows, 'inclusion', checkpointCovered)),
    confirmed: state.kind === 'closed'
  })
  // UX §3 "Left: the event in words" -- role, peer, model, tokens, duration,
  // all read from this row's own record (the fetched `localRecord`, else the
  // body the pane sent with the pair). Any field the record doesn't carry is
  // left out, never a placeholder. The ids move into the expansion.
  const ownRecord = localRecord ?? (row.raw.mine.record as CapsuleRecord | undefined) ?? null
  const provenance = ownRecord ? servingProvenance(ownRecord) : null
  // A requester's own record often carries no model details, usage or
  // latency; the other side's sealed record does. Ours first, theirs
  // labelled as theirs -- never a count presented as our own.
  const theirRecord = (row.raw.theirs.record as CapsuleRecord | undefined) ?? null
  const theirProvenance = theirRecord ? servingProvenance(theirRecord) : null
  const modelRef = provenance?.model ?? theirProvenance?.model ?? null
  const modelIdentity = rowModelName(provenance, theirProvenance)
  const ownTokens = provenance ? tokenFlowText(provenance.promptTokens, provenance.completionTokens) : null
  const theirTokens = theirProvenance
    ? tokenFlowText(theirProvenance.promptTokens, theirProvenance.completionTokens)
    : null
  const tokens = ownTokens ?? (theirTokens ? `${theirTokens} (their count)` : null)
  const ownDuration = ownRecord ? durationText(pocBlock(ownRecord).latency_ms) : null
  const theirDuration = theirRecord ? durationText(pocBlock(theirRecord).latency_ms) : null
  const duration = ownDuration ?? (theirDuration ? `${theirDuration} (their measure)` : null)
  const tone = rowStateTone(state.kind)

  // Chip-strip -> checks-panel jump (§3A "each chip a link into the expansion's matching check"). A chip
  // click on an already-collapsed panel must expand it first and wait for
  // `SecurityChecksView` to actually mount before a `getElementById` lookup
  // can find anything -- `pendingScrollKeyRef` carries the target across
  // that one render; a chip click while already expanded scrolls straight
  // away.
  const pendingScrollKeyRef = useRef<string | null>(null)
  const [highlightedCheckKey, setHighlightedCheckKey] = useState<string | null>(null)

  function scrollToCheck(propertyKey: string) {
    document.getElementById(checkRowDomId(row.exchangeKey, propertyKey))?.scrollIntoView({ block: 'nearest' })
    setHighlightedCheckKey(propertyKey)
    window.setTimeout(() => {
      setHighlightedCheckKey((prev) => (prev === propertyKey ? null : prev))
    }, 1500)
  }

  function handleChipActivate(propertyKey: string) {
    if (checksExpanded) {
      scrollToCheck(propertyKey)
      return
    }
    pendingScrollKeyRef.current = propertyKey
    onToggleChecks(row)
  }

  useEffect(() => {
    if (!checksExpanded || !pendingScrollKeyRef.current) return
    const propertyKey = pendingScrollKeyRef.current
    pendingScrollKeyRef.current = null
    scrollToCheck(propertyKey)
    // eslint-disable-next-line react-hooks/exhaustive-deps -- scrollToCheck closes over this render's row/state; re-running on checksExpanded alone is the intended trigger
  }, [checksExpanded])

  return (
    <div className="flex flex-col" id={exchangeRowDomId(row.exchangeKey)}>
      {rail.isSegmentStart && row.sessionId ? (
        <p className="pl-3 pt-2 type-caption font-mono text-fg-faint">session {row.sessionId}</p>
      ) : null}
      <div
        aria-current={highlighted ? 'true' : undefined}
        aria-label={`Exchange ${row.exchangeKey}`}
        className={cn(
          'flex flex-col gap-2 border-l-2 py-3 pl-3 pr-1',
          rail.hasRail ? 'border-accent/50' : 'border-transparent',
          focused && 'ring-1 ring-inset ring-accent/70',
          highlighted && 'bg-[color-mix(in_oklab,var(--color-accent)_10%,transparent)]'
        )}
        data-focused={focused ? 'true' : undefined}
        data-highlighted={highlighted ? 'true' : undefined}
        data-right-cell-state={state.kind}
        data-role-tag={row.roleTag}
        role="group"
      >
        <div className="grid grid-cols-2 gap-0 rounded border border-border-soft">
          <div className="flex flex-col gap-1 border-r border-border-soft px-3 py-2">
            <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-fg-dim">
              {row.raw.referee_call ? (
                <span
                  className="rounded border border-border-soft px-1 text-[10px] uppercase tracking-wide text-fg-dim"
                  data-referee-call="true"
                >
                  referee answer
                </span>
              ) : null}
              <time className="font-mono tabular-nums" dateTime={row.timestamp ?? undefined}>
                {formatExchangeTimestamp(row.timestamp)}
              </time>
            </p>
            {/* Real text separators (not CSS gaps), so a copy or a screen
               reader gets "You asked key:… · model · 46 → 2 tokens". */}
            <p className="text-xs text-foreground" data-event-line="true">
              <span className="font-medium">{roleText(row.roleTag)}</span>{' '}
              {otherSide ? (
                <span className="font-mono" title={otherSide}>
                  {otherSideName}
                </span>
              ) : (
                <span className="text-fg-dim">other side not recorded</span>
              )}
              {modelIdentity ? (
                <>
                  <span className="text-fg-faint"> · </span>
                  <span className="font-mono" title={modelRef ?? undefined}>
                    {modelIdentity}
                  </span>
                </>
              ) : null}
              {tokens ? (
                <>
                  <span className="text-fg-faint"> · </span>
                  <span className="tabular-nums">{tokens}</span>
                </>
              ) : null}
              {duration ? (
                <>
                  <span className="text-fg-faint"> · </span>
                  <span className="tabular-nums">{duration}</span>
                </>
              ) : null}
            </p>
            <RowVerdictLine row={row.raw} />
          </div>
          <div className="flex flex-col gap-1.5 px-3 py-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="inline-flex items-center gap-1">
                <p className="font-mono text-[11px] text-fg-faint" data-bracket-strip="true">
                  {strip}
                </p>
                <InfoHover census="row:combination" describes="this row as a whole" label={combination} side="left" />
              </span>
              <span className="inline-flex items-center gap-1" data-row-tone={tone}>
                {/* L-A/L-B: only CONTRADICTED gets the alarm dot; the tone
                   (§3A "one colour per state") still varies with CLOSED/
                   refused/absent, never just alarm-vs-muted. */}
                <StatusBadge dot={alarm} size="caption" tone={localOnly || failed ? 'muted' : tone}>
                  {failed
                    ? FAILED_LABEL
                    : localOnly
                      ? NO_OTHER_SIDE_LABEL
                      : rowStatusLabel(state, row.raw.theirs.in_their_log)}
                </StatusBadge>
                {/* Terse state on the face; the fuller story behind the (i). */}
                <InfoHover
                  census={failed ? 'row_state:failed' : localOnly ? 'row_state:local' : `row_state:${state.kind}`}
                  describes={
                    failed
                      ? `the ${FAILED_LABEL} state`
                      : localOnly
                        ? `the ${NO_OTHER_SIDE_LABEL} state`
                        : `the ${rightCellStatusLabel(state)} state`
                  }
                  label={
                    failed
                      ? FAILED_TOOLTIP
                      : localOnly
                      ? LOCAL_ONLY_TOOLTIP
                      : servedForPay && gatedByCounterparty
                        ? SERVED_FOR_PAY_NO_PAYER_TOOLTIP
                        : rightCellDetail(state)
                  }
                  side="left"
                />
              </span>
            </div>
            <p className="inline-flex flex-wrap items-center gap-1 text-xs text-foreground" data-right-cell-text="true">
              <span data-row-verdict-text="true">{faceText}</span>
              {verdictDetail ? (
                <span
                  className="inline-flex"
                  data-ask-reply-verified={askNote ? (askNote.verified ? 'true' : 'false') : undefined}
                  data-ask-reply-witness={askNote?.witness}
                  data-ask-retry={retryNote ? 'true' : undefined}
                  data-verdict-detail="true"
                >
                  <InfoHover census="row:verdict_detail" describes="this verdict" label={verdictDetail} side="left" />
                </span>
              ) : null}
            </p>
            {ownRecordFails ? (
              <p className="text-xs text-bad" data-own-record-fails="true" role="note">
                {OWN_RECORD_FAILS_WARNING}
              </p>
            ) : null}
            {historyLine ? (
              <p
                className={cn('text-xs', historyLine.verified ? 'text-foreground' : 'text-fg-dim')}
                data-history-reply-verified={historyLine.verified ? 'true' : 'false'}
                data-history-witness={historyLine.witness}
                role="note"
              >
                {historyLine.text}
                {historyLine.checkedLine ? (
                  <span className="text-fg-faint" data-history-checked="true">
                    {' '}
                    · {historyLine.checkedLine}
                  </span>
                ) : null}
                {historyLine.detail ? (
                  <>
                    {' '}
                    <InfoHover census="row:history_detail" describes="their history" label={historyLine.detail} side="left" />
                  </>
                ) : null}
              </p>
            ) : null}
            <div className="flex flex-wrap items-center gap-1.5" data-row-asks="true">
              {action ? (
                // Compare opens this row's checks at "their record", where
                // yours and theirs sit side by side.
                <Button
                  className={ROW_BUTTON_CLASS}
                  onClick={() => handleChipActivate(entryRowChipPropertyKey('theirs'))}
                  size="sm"
                  type="button"
                  variant="outline"
                >
                  {action}
                </Button>
              ) : null}
              {/* Only where their half did not arrive: a row holding both
                 halves, or their signed answer, has nothing to request. */}
              {isWaitingForTheirRecord(state.kind) ? (
                <AskButton
                  census="action:disabled_reason"
                  control={asks.record}
                  onAsk={() => {
                    if (askFor && onAskForRecord) onAskForRecord(row, askFor)
                  }}
                />
              ) : null}
              <AskButton
                census="action:disabled_reason"
                control={asks.history}
                onAsk={() => {
                  if (askPeer && onAskForHistory) onAskForHistory(row, askPeer)
                }}
              />
            </div>
          </div>
        </div>
        <RowSteps steps={steps} />
        {row.raw.split ? <StageStrip split={row.raw.split} /> : null}
        {/* Payments sit beside the inference state, never inside it: CLOSED
           is about the two records of the exchange; settlement is this
           node's own payment records for it. */}
        <SettlementStrip settlement={row.raw.settlement} />
        <ProviderSettlementStrip requester={row.raw.counterparty} settlement={row.raw.provider_settlement} />
        <AgreementStrip
          agreement={row.raw.agreement}
          paid={Boolean(row.raw.settlement || row.raw.provider_settlement)}
        />
        <ReceiptPanel row={row.raw} />
        {/* v3 §2's row footer: two independent
           disclosure toggles, never a modal. Always present, regardless of
           the right-cell state. */}
        <div className="flex items-center gap-3 text-xs text-fg-dim">
          <button
            aria-expanded={contentExpanded}
            className="ui-control-ghost font-mono"
            onClick={() => onToggleContent(row)}
            type="button"
          >
            {contentExpanded ? 'What was said ▾' : 'What was said ▸'}
          </button>
          <button
            aria-expanded={checksExpanded}
            className="ui-control-ghost font-mono"
            onClick={() => onToggleChecks(row)}
            type="button"
          >
            {checksExpanded ? 'How we checked ▾' : 'How we checked ▸'}
          </button>
        </div>
        {contentExpanded ? (
          <div className="grid grid-cols-2 gap-0 rounded border border-border-soft" data-content-toggle="expanded">
            <div
              className="flex flex-col gap-1 border-r border-border-soft px-3 py-2"
              data-your-content-state={row.contentToggleState.your.kind}
            >
              {row.contentToggleState.your.kind === 'populated' ? (
                <>
                  <p className="text-xs text-foreground">
                    <span className="text-fg-faint">You asked</span> · {row.raw.mine.text ?? '—'}
                  </p>
                  {row.raw.mine.reply_text ? (
                    <p className="text-xs text-foreground">
                      <span className="text-fg-faint">They streamed back</span> · {row.raw.mine.reply_text}
                    </p>
                  ) : null}
                </>
              ) : (
                <p className="text-xs text-foreground">{yourContentFixedText(row.contentToggleState.your)}</p>
              )}
            </div>
            <div
              className="flex flex-col gap-1.5 px-3 py-2"
              data-their-content-state={row.contentToggleState.their.kind}
            >
              <p className="text-xs text-fg-dim">{theirContentText(row.contentToggleState.their)}</p>
            </div>
          </div>
        ) : null}
        {checksExpanded ? (
          // The per-check chips: each a link to its check below.
          <ExchangeRowChips
            checkpointCovered={checkpointCovered}
            checks={checksRows}
            onChipActivate={handleChipActivate}
            witnessOff={witnessOff}
          />
        ) : null}
        {checksExpanded ? (
          // UX §3: the engineer's facts lead the expansion -- the CLOSED
          // per-property cells (each restating a fact the gate established),
          // then the full ids that used to sit on the row face.
          <div className="flex flex-wrap items-center gap-1.5 font-mono text-xs" data-expansion-head="true">
            {state.kind === 'closed'
              ? closedPropertyCellItems(row.raw).map((cell) => (
                  <span
                    className="inline-flex items-center gap-1 rounded border border-border-soft px-1.5 py-0.5 text-[11px] text-fg-dim"
                    data-closed-property-cell={cell.key}
                    key={cell.key}
                  >
                    {cell.label}
                    <InfoHover census={`closed_cell:${cell.key}`} describes={cell.label} label={cell.tooltip} />
                  </span>
                ))
              : null}
            <CopyableId label="exchange" value={row.exchangeKey} />
            <SeeInLogsLink exchangeKey={row.exchangeKey} />
            <span className="text-fg-faint">·</span>
            {(row.raw.mine.capsule_id ?? row.raw.mine.text) ? (
              <CopyableId label="record" value={(row.raw.mine.capsule_id ?? row.raw.mine.text) as string} />
            ) : (
              <span className="inline-flex items-center gap-1">
                <span className="text-fg-faint">record</span>
                <span>—</span>
              </span>
            )}
          </div>
        ) : null}
        {checksExpanded ? <SettlementEntries settlement={row.raw.settlement} /> : null}
        {checksExpanded ? (
          <SettlementEntries perspective="provider" settlement={row.raw.provider_settlement} />
        ) : null}
        {checksExpanded ? (
          <SecurityChecksView
            checksRows={checksRows}
            highlightedPropertyKey={highlightedCheckKey}
            identity={identity}
            localRecord={localRecord}
            otherRow={otherRow}
            row={row}
            theirsRecompute={theirsRecompute}
          />
        ) : null}
      </div>
    </div>
  )
}
