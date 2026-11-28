// The precedence rules of `row-evidence.ts`, as a table: each row is one
// combination of their records, their claims and our asks, and what the row
// must show for it.
import { describe, expect, it } from 'vitest'
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'
import { settleRowAsk, type AskOutcome, type RowAsk } from '@/features/capsules/lib/ask-for-record'
import { fullTimeInstant, type RightCellStateKind } from '@/features/capsules/lib/exchange-row-state'
import { FIXTURE_REQUEST_DIGEST, fixtureHalfBody } from '@/features/capsules/lib/pushed-half-fixtures'
import type { PeerRecomputeState } from '@/features/capsules/lib/recompute-identity'
import { judgeRow, type EvidenceSource } from '@/features/capsules/lib/row-evidence'

const T1 = '2026-09-28T21:00:00Z'
const T2 = '2026-09-28T22:00:00Z'

/** Our record of the exchange: requested, served by the fixture provider. */
function ours(): Record<string, unknown> {
  const body = fixtureHalfBody({ capsuleId: 'ours-1' })
  const poc = (body.model_attestation as Record<string, Record<string, Record<string, unknown>>>).compute_attestation[
    'x-mesh-poc-v1'
  ]
  poc.role = 'requested'
  return body
}

type Body = 'agrees' | 'disagrees' | 'other_provider' | 'other_exchange'
function body(kind: Body): Record<string, unknown> {
  switch (kind) {
    case 'agrees':
      return fixtureHalfBody({ capsuleId: 't-agrees' })
    case 'disagrees':
      return fixtureHalfBody({ capsuleId: 't-disagrees', responseDigest: 'e'.repeat(64) })
    case 'other_provider':
      return fixtureHalfBody({ capsuleId: 't-other', servedBy: 'd'.repeat(64) })
    case 'other_exchange':
      return { ...fixtureHalfBody({ capsuleId: 't-unnamed' }), effect: {} }
  }
}

type Check = { idMatch: boolean; signatureOk: boolean }
const VERIFIED: Check = { idMatch: true, signatureOk: true }
const ID_MISMATCH_SIGNED: Check = { idMatch: false, signatureOk: true }
const ID_MISMATCH_UNSIGNED: Check = { idMatch: false, signatureOk: false }
const BAD_SIGNATURE: Check = { idMatch: true, signatureOk: false }

function record(kind: Body, check: Check = VERIFIED): PeerRecomputeState {
  return { status: 'found', ...check, peerRecord: body(kind), fetch: () => {} }
}

/** The row as the pane sends it: a known peer, optionally a pushed record and
 *  the pane's own evidence outcome. */
function paneRow(opts: { pushed?: PeerRecomputeState; outcome?: string; outcomeDate?: string; absent?: boolean } = {}) {
  const theirs: Record<string, unknown> = opts.absent
    ? { state: 'absent', capsule_id: null }
    : { state: 'NOT_CHECKED', capsule_id: 'a'.repeat(64), peer_id: 'c'.repeat(64) }
  if (opts.pushed) {
    theirs.record = opts.pushed.peerRecord
    theirs.signature_ok = opts.pushed.signatureOk
    theirs.id_match = opts.pushed.idMatch
  }
  if (opts.outcome) {
    theirs.evidence_outcome = opts.outcome
    theirs.evidence_outcome_date = opts.outcomeDate
  }
  return { exchange_key: `digest:${FIXTURE_REQUEST_DIGEST}`, mine: { state: 'present', record: ours() }, theirs } as unknown as PaneCRow
}

// A witnessed reply unless a case says otherwise (`askReplyNote`).
const asked = (
  evidence: PeerRecomputeState,
  at = T1,
  witness: 'witnessed' | 'unwitnessed' | 'no_witness' = 'witnessed'
): AskOutcome => ({ kind: 'record', at, evidence, witness })
const refused = (at = T1): AskOutcome => ({ kind: 'refused', at, reason: 'not_authorized' })
const noRecord = (at = T1): AskOutcome => ({ kind: 'no_record', at })
const failed = (at = T2): AskOutcome => ({ kind: 'no_reply', at, detail: 'HTTP 502' })

function asks(...outcomes: AskOutcome[]): RowAsk | null {
  let ask: RowAsk | null = null
  for (const outcome of outcomes) ask = settleRowAsk(ask, outcome, ours() as never, null)
  return ask
}

type Case = {
  name: string
  row?: PaneCRow
  fetched?: PeerRecomputeState
  ask?: RowAsk | null
  state: RightCellStateKind
  date?: string | null
  source?: EvidenceSource | null
  askNote?: { verified: boolean; text: RegExp } | null
  retry?: RegExp | null
}

const CASES: Case[] = [
  // Rule 2: only a verified record gives a verdict -- except an altered one
  // (contents don't produce its id), which is Disagree per the ratified
  // bilateral-retention-decay-property.
  { name: 'a verified confirming fetch is Confirmed', fetched: record('agrees'), state: 'closed', source: 'fetched' },
  { name: 'a verified disagreeing fetch is Disagree', fetched: record('disagrees'), state: 'contradicted', source: 'fetched' },
  {
    name: 'a fetched record whose contents don’t produce its id is Disagree, even with a valid signature',
    fetched: record('agrees', ID_MISMATCH_SIGNED),
    state: 'contradicted',
    source: 'fetched'
  },
  {
    name: 'an unsigned pushed record from the provider with a mismatched id is Disagree',
    row: paneRow({ pushed: record('agrees', ID_MISMATCH_UNSIGNED) }),
    state: 'contradicted',
    source: 'pushed'
  },
  {
    name: 'a pushed record with a mismatched id from a node that didn’t serve us is no verdict (anyone can push)',
    row: paneRow({ pushed: record('other_provider', ID_MISMATCH_UNSIGNED) }),
    state: 'open_not_held',
    source: 'pushed'
  },
  {
    name: 'an asked record whose contents don’t produce its id is Disagree, and its note says so',
    ask: asks(asked(record('agrees', ID_MISMATCH_UNSIGNED))),
    state: 'contradicted',
    source: 'asked',
    askNote: { verified: true, text: /^Their record doesn’t match its own id, so it isn’t the record that was sealed\.$/ }
  },
  {
    name: 'a bad signature over a matching id is no verdict, even if its answer differs',
    ask: asks(asked(record('disagrees', BAD_SIGNATURE))),
    state: 'open_asked',
    askNote: { verified: false, text: /^Their record didn’t check out \(it is not signed with the key this node has for them\)\.$/ }
  },
  // Rule 3: Disagree beats Confirmed whatever the source.
  {
    name: 'pushed confirming + asked contradicting -> Disagree, showing the asked record',
    row: paneRow({ pushed: record('agrees') }),
    ask: asks(asked(record('disagrees'))),
    state: 'contradicted',
    source: 'asked',
    askNote: { verified: true, text: /^Their reply is verified/ }
  },
  {
    name: 'asked confirming + pushed contradicting -> Disagree, showing the pushed record',
    row: paneRow({ pushed: record('disagrees') }),
    ask: asks(asked(record('agrees'))),
    state: 'contradicted',
    source: 'pushed',
    retry: /^Asked .*: their record matches yours\.$/
  },
  {
    name: 'live fetch contradicting + pushed confirming -> Disagree, showing the fetch',
    row: paneRow({ pushed: record('agrees') }),
    fetched: record('disagrees'),
    state: 'contradicted',
    source: 'fetched'
  },
  {
    name: 'the door’s refusal of a pushed record beats an asked confirming record',
    row: paneRow({ outcome: 'claims_refused' }),
    ask: asks(asked(record('agrees'))),
    state: 'contradicted'
  },
  {
    name: 'an asked verified confirming record is Confirmed, its note verified',
    ask: asks(asked(record('agrees'))),
    state: 'closed',
    source: 'asked',
    askNote: { verified: true, text: /^Their reply is verified: the record is in their log/ }
  },
  {
    name: 'an asked confirming record no witness vouches for is still Confirmed, but its note never says verified',
    ask: asks(asked(record('agrees'), T1, 'unwitnessed')),
    state: 'closed',
    source: 'asked',
    askNote: { verified: false, text: /^Their record checks against their own signatures only: .*could be a private copy$/ }
  },
  {
    name: 'an asked confirming record with no witness configured is still Confirmed, its note says there was none',
    ask: asks(asked(record('agrees'), T1, 'no_witness')),
    state: 'closed',
    source: 'asked',
    askNote: { verified: false, text: /This node has no witness configured to check it against/ }
  },
  // A verdict wins over a failed ask, and the attempt stays visible.
  {
    name: 'a failed ask, then their pushed record confirms -> Confirmed, the ask said on its own line',
    row: paneRow({ pushed: record('agrees') }),
    ask: asks(failed()),
    state: 'closed',
    source: 'pushed',
    retry: /^Asked .*: no verified reply \(HTTP 502\)\.$/
  },
  {
    name: 'a kept contradicting asked record survives a later bad-signature record, even beside a confirming push',
    row: paneRow({ pushed: record('agrees') }),
    ask: asks(asked(record('disagrees')), asked(record('agrees', BAD_SIGNATURE), T2)),
    state: 'contradicted',
    source: 'asked',
    retry: /^Asked again .*: their record didn’t check out \(it is not signed with the key this node has for them\)\.$/
  },
  {
    name: 'a kept contradiction survives a later validly signed other_provider record',
    
    ask: asks(asked(record('disagrees')), asked(record('other_provider'), T2)),
    state: 'contradicted',
    source: 'asked',
    retry: /^Asked again .*: their record checks out but doesn’t confirm this exchange: it isn’t from the node that served you\.$/
  },
  {
    name: 'a kept contradiction survives a later validly signed other_provider record beside a confirming push',
    row: paneRow({ pushed: record('agrees') }),
    ask: asks(asked(record('disagrees')), asked(record('other_provider'), T2)),
    state: 'contradicted',
    source: 'asked',
    retry: /^Asked again .*: their record checks out but doesn’t confirm this exchange: it isn’t from the node that served you\.$/
  },
  {
    name: 'a kept contradiction survives a later validly signed other_exchange record',
    
    ask: asks(asked(record('disagrees')), asked(record('other_exchange'), T2)),
    state: 'contradicted',
    source: 'asked',
    retry: /^Asked again .*: their record checks out but doesn’t confirm this exchange: it doesn’t name your request and answer\.$/
  },
  {
    name: 'a kept contradiction survives a later validly signed other_exchange record beside a confirming push',
    row: paneRow({ pushed: record('agrees') }),
    ask: asks(asked(record('disagrees')), asked(record('other_exchange'), T2)),
    state: 'contradicted',
    source: 'asked',
    retry: /^Asked again .*: their record checks out but doesn’t confirm this exchange: it doesn’t name your request and answer\.$/
  },
  // Rule 4: the newest verified claim.
  {
    name: 'a failed retry never replaces their verified refusal',
    ask: asks(refused(), failed()),
    state: 'open_refused',
    date: T1,
    // The decline gives its reason in plain words, never the token.
    askNote: {
      verified: true,
      text: /^Signed refusal, .+: their sharing settings don’t let them send it to this node\. Their reply is verified/
    },
    retry: /^Asked again .*: no verified reply \(HTTP 502\)\.$/
  },
  {
    name: 'a retry the tool couldn’t send says so in plain words, never the tool’s error',
    ask: asks(refused(), { kind: 'no_reply', at: T2, detail: 'That node isn’t on the mesh now, so it can’t be asked.', plain: true }),
    state: 'open_refused',
    retry: /^Asked again .*: that node isn’t on the mesh now, so it can’t be asked\.$/
  },
  {
    name: 'a refused retry names its reason in the line',
    ask: asks(noRecord(), { kind: 'refused', at: '2026-09-28T23:59:00Z', reason: 'retention_expired' }),
    state: 'open_refused',
    askNote: { verified: true, text: /: they no longer keep it\. / }
  },
  {
    name: 'an ambiguous retry never replaces their verified "no record"',
    ask: asks(noRecord(), { kind: 'ambiguous', at: T2, count: 2 }),
    state: 'open_absent',
    retry: /^Asked again .*: their reply carried 2 records that could be theirs; none is shown as theirs\.$/
  },
  {
    name: 'a retry returning a bad-signature record never replaces the refusal; the line says it didn’t check out',
    ask: asks(refused(), asked(record('agrees', BAD_SIGNATURE), T2)),
    state: 'open_refused',
    retry: /^Asked again .*: their record didn’t check out \(it is not signed with the key this node has for them\)\.$/
  },
  {
    name: 'a retry returning an altered record is Disagree: a verdict beats the earlier refusal',
    ask: asks(refused(), asked(record('agrees', ID_MISMATCH_UNSIGNED), T2)),
    state: 'contradicted',
    source: 'asked'
  },
  {
    name: 'a retry returning a verified record from another provider: refusal stands, line says why',
    ask: asks(refused(), asked(record('other_provider'), T2)),
    state: 'open_refused',
    retry: /^Asked again .*: their record checks out but doesn’t confirm this exchange: it isn’t from the node that served you\.$/
  },
  {
    name: 'an in-flight retry shows no line and keeps the refusal',
    ask: asks(refused(), { kind: 'asking', at: T2 }),
    state: 'open_refused',
    retry: null
  },
  {
    name: 'claims arriving in reverse signed order: the newer (T2) refusal stands, the T1 attempt is the retry line',
    ask: asks(refused('2026-09-28T22:00:05Z'), noRecord('2026-09-28T21:00:05Z')),
    state: 'open_refused',
    date: '2026-09-28T22:00:05Z',
    askNote: { verified: true, text: /^Signed refusal, .+: .+\. Their reply is verified/ },
    retry: /^Asked again .*: they say they have no record of this, signed\.$/
  },
  {
    name: 'a stale ask claim never masks a newer pane claim',
    row: paneRow({ outcome: 'signed_refusal', outcomeDate: '2026-09-29T10:00:00Z' }),
    ask: asks(noRecord('2026-09-28T21:00:05Z')),
    state: 'open_refused',
    date: '2026-09-29T10:00:00Z',
    askNote: null,
    retry: /^Asked .*: they say they have no record of this, signed\.$/
  },
  {
    name: 'a newer ask claim replaces an older pane claim',
    row: paneRow({ outcome: 'signed_refusal', outcomeDate: '2026-09-27T10:00:00Z' }),
    ask: asks(noRecord('2026-09-28T21:00:05Z')),
    state: 'open_absent',
    date: '2026-09-28T21:00:05Z'
  },
  {
    name: 'a pane claim with no full time wins over an ask claim',
    row: paneRow({ outcome: 'recorded_absence', outcomeDate: '4 Sep' }),
    ask: asks(refused()),
    state: 'open_absent',
    date: '4 Sep'
  },
  // Rules 6 + 7.
  {
    name: 'a verified record for another exchange is never "Their reply is verified" beside "Asked, no reply"',
    ask: asks(asked(record('other_exchange'))),
    state: 'open_asked',
    askNote: {
      verified: false,
      text: /^Their record checks out but doesn’t confirm this exchange: it doesn’t name your request and answer\.$/
    },
    retry: null
  },
  {
    name: 'a first ask that fails: Asked, and why',
    ask: asks(failed()),
    state: 'open_asked',
    askNote: { verified: false, text: /^No verified reply \(HTTP 502\)\.$/ },
    retry: null
  },
  { name: 'nothing at all: the pane’s own state', state: 'open_not_held', source: null, askNote: null, retry: null }
]

describe('judgeRow: the precedence of records, claims and asks', () => {
  it.each(CASES)('$name', (c) => {
    const judged = judgeRow(c.row ?? paneRow(), ours() as never, c.fetched ?? null, c.ask ?? null)
    expect(judged.state.kind).toBe(c.state)
    if (c.date !== undefined) expect(judged.state.date).toBe(c.date)
    if (c.source !== undefined) expect(judged.source).toBe(c.source)
    if (c.askNote !== undefined) {
      if (c.askNote === null) expect(judged.askNote).toBeNull()
      else {
        expect(judged.askNote?.verified).toBe(c.askNote.verified)
        expect(judged.askNote?.text).toMatch(c.askNote.text)
      }
    }
    if (c.retry !== undefined) {
      if (c.retry === null) expect(judged.retryNote).toBeNull()
      else expect(judged.retryNote).toMatch(c.retry)
    }
  })

  it('the record shown is the verdict’s record, so the panel and Compare compare it', () => {
    const contradicting = record('disagrees')
    const judged = judgeRow(paneRow({ pushed: record('agrees') }), ours() as never, null, asks(asked(contradicting)))
    expect(judged.evidence?.peerRecord).toBe(contradicting.peerRecord)
  })
})

describe('settleRowAsk: which verified claim is kept', () => {
  it('keeps the newest by signed time, whatever the arrival order; latest is still the last attempt', () => {
    const t2 = refused('2026-09-28T22:00:05Z')
    const t1 = noRecord('2026-09-28T21:00:05Z')
    const ask = asks(t2, t1)
    expect(ask?.claim).toBe(t2)
    expect(ask?.latest).toBe(t1)
    expect(asks(t1, t2)?.claim).toBe(t2)
  })

  it('without full times, a new claim replaces the stored one only when it says something different', () => {
    const first = refused('4 Sep')
    expect(asks(first, refused('5 Sep'))?.claim).toBe(first)
    const different = noRecord('5 Sep')
    expect(asks(first, different)?.claim).toBe(different)
  })
})

describe('settleRowAsk: only a record that gives this row a verdict is kept', () => {
  it('a later validly signed record that reaches no verdict only updates latest', () => {
    const contradicting = asked(record('disagrees'))
    for (const kind of ['other_provider', 'other_exchange'] as const) {
      const later = asked(record(kind), T2)
      const ask = asks(contradicting, later)
      expect(ask?.record).toBe(contradicting)
      expect(ask?.latest).toBe(later)
    }
  })

  it('a later record that does give a verdict replaces the kept one', () => {
    const confirming = asked(record('agrees'), T2)
    expect(asks(asked(record('disagrees')), confirming)?.record).toBe(confirming)
  })
})

describe('fullTimeInstant', () => {
  it('names an instant only for a full RFC 3339 time with a zone that parses to a real time', () => {
    expect(fullTimeInstant('2026-09-28T21:00:00Z')).toBe(Date.parse('2026-09-28T21:00:00Z'))
    expect(fullTimeInstant('2026-09-28T23:00:00+02:00')).toBe(Date.parse('2026-09-28T21:00:00Z'))
    for (const bad of ['2026-99-28T21:00:00Z', '2026-09-28T21:00:00', '4 Sep', '', null, undefined]) {
      expect(fullTimeInstant(bad)).toBeNull()
    }
  })

  it('a claim whose time names no real instant falls back to the kind rule', () => {
    const impossible = refused('2026-99-28T21:00:00Z')
    expect(asks(impossible, refused('2026-09-28T21:00:00Z'))?.claim).toBe(impossible)
    const different = noRecord('2026-09-28T21:00:00Z')
    expect(asks(impossible, different)?.claim).toBe(different)
  })
})
