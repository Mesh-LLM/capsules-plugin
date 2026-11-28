// What one Exchanges row shows about the other side: its state, the record of
// theirs the badge, the checks panel and Compare all use, and the lines about
// asking. Every source is weighed here, by these rules and nothing else:
//
//   1. Candidates. Records: the live fetch this browser ran, the record the
//      pane correlated from a push, the record the latest ask returned, and
//      the last record an ask returned that can give a verdict
//      (`settleRowAsk`). Claims:
//      the pane's own outcome (their signed refusal or "no record", or the
//      door's refusal of a pushed record that named another server or model)
//      and an ask's verified refusal or "no record". Of several asks' claims,
//      the one kept is the newest by signed time when both carry a full
//      RFC 3339 time; without that, a new claim replaces the stored one only
//      when it says something different (refusal vs "no record").
//      `RowAsk.latest` is always the most recent attempt.
//   2. A record sets a verdict only when it is VERIFIED: its contents produce
//      its id and its signature holds under the key this node has for them
//      (`isVerifiedRecord`). The one exception: a record whose contents
//      demonstrably don't produce the id it claims (a completed check,
//      idMatch === false) is Disagree -- the other side handed over an
//      altered record, the "both present, disagreeing" case of the ratified
//      bilateral-retention-decay-property (agent-action-capsule @7f8a78d8);
//      a pushed one from a node that didn't serve the exchange excepted. A
//      bad signature over a matching id, or an id check that couldn't run,
//      is no verdict (`recordVerdict`).
//   3. Among verified records (and the door's refusal), any Disagree wins,
//      and that record is the one shown; otherwise any Confirmed wins.
//      Disagree beats Confirmed whatever the source, so a confirming record
//      can never hide a contradicting one.
//   4. With no verdict, the newest verified claim stands: the pane's or the
//      ask's, compared by the claim's signed time when both carry a full
//      RFC 3339 time; otherwise the pane's wins over the ask's.
//   5. The latest ask is always visible. When it isn't what the row shows, a
//      line says what it returned ("Asked again {time}: …").
//   6. A note never says "verified" for something the badge doesn't show: a
//      verified record that reaches no verdict says what it is instead.
//   7. With no verdict and no claim: "asked" once an ask was sent, else the
//      pane's own state (not held / not given / not asked).
//
// The record shown (`evidence`) is the verdict's record, else the first record
// held in the order above, so the checks panel always compares the record the
// row is talking about.
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'
import type { CapsuleRecord } from '@/features/capsules/api/types'
import {
  askReplyNote,
  recordProblems,
  recordRefusalWords,
  type AskOutcome,
  type RowAsk
} from '@/features/capsules/lib/ask-for-record'
import {
  deriveRightCellState,
  fullTimeInstant,
  isVerifiedRecord,
  paneOutcomeState,
  pushedHalfRecompute,
  recordVerdict,
  servedBinding,
  type RecordVerdict,
  type RightCellState
} from '@/features/capsules/lib/exchange-row-state'
import { formatExchangeTimestamp } from '@/features/capsules/lib/local-time'
import type { PeerRecomputeState } from '@/features/capsules/lib/recompute-identity'

export type EvidenceSource = 'fetched' | 'pushed' | 'asked'

export type RowJudgement = {
  state: RightCellState
  /** The record of theirs the badge, the checks panel and Compare use. */
  evidence: PeerRecomputeState | null
  source: EvidenceSource | null
  /** What an ask returned, when it is what the row shows, or when nothing
   *  verified is shown: `verified` only for what the badge shows. A record's
   *  note carries its `witness` standing (`askReplyNote`). */
  askNote: ReturnType<typeof askReplyNote>
  /** The latest ask, when the row shows something else verified. */
  retryNote: string | null
  /** Confirmed from a record an ask brought that the plugin couldn't save
   *  on this node: a reload won't keep the confirmation. */
  confirmedUnsaved: boolean
}

type RecordCandidate = {
  source: EvidenceSource
  evidence: PeerRecomputeState
  verdict: RecordVerdict
  /** The ask outcome this record came from, for an asked record. */
  outcome: AskOutcome | null
}

const instant = fullTimeInstant

/** A record of theirs whose contents don't produce the id it claims. */
const ALTERED = 'their record doesn’t match its own id, so it isn’t the record that was sealed'

const NO_VERDICT_WHY: Record<Exclude<RecordVerdict, { kind: 'closed' } | { kind: 'contradicted' }>['why'], string> = {
  not_verified: 'it didn’t check out',
  other_provider: 'it isn’t from the node that served you',
  other_exchange: 'it doesn’t name your request and answer'
}

/** What the latest ask returned, in a few words, for the line under the row. */
function attemptText(outcome: AskOutcome, verdict: RecordVerdict | null): string | null {
  switch (outcome.kind) {
    case 'asking':
      return null
    case 'no_reply':
      // A tool failure is already a whole plain sentence: said as a clause.
      return outcome.plain
        ? `${outcome.detail.charAt(0).toLowerCase()}${outcome.detail.slice(1).replace(/\.$/, '')}`
        : `no verified reply (${outcome.detail})`
    case 'ambiguous':
      return `their reply carried ${outcome.count} records that could be theirs; none is shown as theirs`
    case 'refused':
      return `they declined (${recordRefusalWords(outcome.reason)}), and signed the refusal`
    case 'no_record':
      return 'they say they have no record of this, signed'
    case 'record': {
      if (!verdict || verdict.kind === 'no_verdict') {
        if (!isVerifiedRecord(outcome.evidence)) return `their record didn’t check out (${recordProblems(outcome.evidence)})`
        const why = verdict?.kind === 'no_verdict' ? NO_VERDICT_WHY[verdict.why] : NO_VERDICT_WHY.other_exchange
        return `their record checks out but doesn’t confirm this exchange: ${why}`
      }
      if (verdict.kind === 'closed') return 'their record matches yours'
      return verdict.why === 'altered' ? ALTERED : 'their record disagrees with yours'
    }
  }
}

export function judgeRow(
  row: PaneCRow,
  localRecord: CapsuleRecord | null | undefined,
  fetched: PeerRecomputeState | null,
  ask: RowAsk | null
): RowJudgement {
  const ours = localRecord ?? (row.mine.record as CapsuleRecord | undefined) ?? null
  const served = servedBinding(row.mine)

  // 1. Candidates.
  const records: RecordCandidate[] = []
  if (fetched?.status === 'found') {
    records.push({ source: 'fetched', evidence: fetched, verdict: recordVerdict(fetched, ours, 'fetched', served), outcome: null })
  }
  const pushed = pushedHalfRecompute(row)
  if (pushed) records.push({ source: 'pushed', evidence: pushed, verdict: recordVerdict(pushed, ours, 'pushed', served), outcome: null })
  // Both the latest asked record and the kept verdict record: a later record
  // that reaches no verdict never hides an earlier one that did.
  const askedRecords = [ask?.latest.kind === 'record' ? ask.latest : null, ask?.record ?? null].filter(
    (o, i, all): o is Extract<AskOutcome, { kind: 'record' }> => o !== null && all.indexOf(o) === i
  )
  for (const askedRecord of askedRecords) {
    records.push({
      source: 'asked',
      evidence: askedRecord.evidence,
      verdict: recordVerdict(askedRecord.evidence, ours, 'asked', served),
      outcome: askedRecord
    })
  }
  const pane = paneOutcomeState(row)
  const askClaim = ask?.claim ?? null

  // 2 + 3. Verified records only; Disagree beats Confirmed.
  const contradicting = records.find((r) => r.verdict.kind === 'contradicted')
  const confirming = records.find((r) => r.verdict.kind === 'closed')
  const doorRefused = pane?.kind === 'contradicted' ? pane : null
  let state: RightCellState
  let shown: RecordCandidate | null = null
  let shownAsk: AskOutcome | null = null
  if (contradicting || doorRefused) {
    shown = contradicting ?? null
    state = contradicting ? { kind: 'contradicted', date: null } : (doorRefused as RightCellState)
  } else if (confirming) {
    shown = confirming
    state = { kind: 'closed', date: null }
  } else {
    // 4. The newest verified claim.
    const paneClaim = pane && (pane.kind === 'open_refused' || pane.kind === 'open_absent') ? pane : null
    const askState: RightCellState | null = askClaim
      ? { kind: askClaim.kind === 'refused' ? 'open_refused' : 'open_absent', date: askClaim.at }
      : null
    const paneAt = instant(paneClaim?.date ?? null)
    const askAt = instant(askState?.date ?? null)
    const askNewer = askState !== null && (paneClaim === null || (paneAt !== null && askAt !== null && askAt > paneAt))
    if (askNewer && askState) {
      state = askState
      shownAsk = askClaim
    } else if (paneClaim) {
      state = paneClaim
    } else if (ask) {
      // 7. Asked, nothing verified to show.
      state = { kind: 'open_asked', date: ask.latest.at }
    } else {
      state = deriveRightCellState(row, undefined, localRecord)
      // The pane's own state without its records judged again: a held
      // record that gave no verdict leaves the row waiting.
      if (state.kind === 'closed' || state.kind === 'contradicted') state = { kind: 'open_not_held', date: null }
    }
  }
  if (shown?.source === 'asked') shownAsk = shown.outcome

  const evidenceRecord = shown ?? records[0] ?? null

  // 5 + 6. The ask lines.
  let askNote: RowJudgement['askNote'] = null
  let retryNote: string | null = null
  if (ask) {
    const latest = ask.latest
    // "Asked again" after an earlier answer that verified; else "Asked".
    const earlier = [ask.claim, ask.record].some((o) => o !== null && o !== latest)
    const asked = earlier ? 'Asked again' : 'Asked'
    const latestVerdict = latest.kind === 'record' ? recordVerdict(latest.evidence, ours, 'asked', served) : null
    if (shownAsk) {
      // An altered record is shown as Disagree: its note says so, never "not
      // verified" beside that badge.
      askNote =
        shownAsk.kind === 'record' && shownAsk.evidence.idMatch === false
          ? { verified: true, text: `${ALTERED.charAt(0).toUpperCase()}${ALTERED.slice(1)}.` }
          : askReplyNote(shownAsk)
      if (latest !== shownAsk) {
        const text = attemptText(latest, latestVerdict)
        if (text) retryNote = `${asked} ${formatExchangeTimestamp(latest.at)}: ${text}.`
      }
    } else {
      const showsVerified = state.kind === 'closed' || state.kind === 'contradicted' || state.kind === 'open_refused' || state.kind === 'open_absent'
      const text = attemptText(latest, latestVerdict)
      if (text && showsVerified) {
        retryNote = `${asked} ${formatExchangeTimestamp(latest.at)}: ${text}.`
      } else if (text) {
        askNote = { verified: false, text: `${text.charAt(0).toUpperCase()}${text.slice(1)}.` }
      }
    }
  }

  return {
    state,
    evidence: evidenceRecord?.evidence ?? null,
    source: evidenceRecord?.source ?? null,
    askNote,
    retryNote,
    confirmedUnsaved:
      state.kind === 'closed' && shown?.source === 'asked' && shown.outcome?.kind === 'record' && shown.outcome.saved === false
  }
}
