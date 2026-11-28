import { describe, expect, it } from 'vitest'
import {
  buildRegistrationCopy,
  buildSetupSteps,
  CAPTURE_BOUNDARY_FACT,
  CHAIN_BAR_INFO,
  coverageBadge,
  checkpointRegistration,
  CONTINUITY_NOT_ESTABLISHED,
  continuityFact,
  coveredRecordCount,
  recordsStripBreakdown,
  recordsStripHeading,
  sealedBreakdownText,
  identityFact,
  INTEGRITY_TILE_INFO,
  RETENTION_FACT,
  witnessKeyProblems,
  witnessRestartNote,
  witnessRows,
  latestWitnessed,
  witnessCoverageByRecord,
  witnessCoverageLine,
  ledgerOrderIds,
  checkpointCoverageByRecord
} from '@/features/capsules/lib/integrity-view'
import { ownerLinked } from '@/features/capsules/lib/integrity-view'
import { formatExchangeTimestamp } from '@/features/capsules/lib/local-time'
import type { RecomputedIdentity } from '@/features/capsules/lib/recompute-identity'
import { buildChecksRows } from '@/features/capsules/lib/security-checks-view'
import { STANDING_WORD } from '@/features/capsules/lib/banned-terms'

describe('buildSetupSteps — three steps named after the attack they guard against', () => {
  it('reads a bare node truthfully: witness off, owner not linked, no exchanges yet', () => {
    const steps = buildSetupSteps({ checkpoint_count: 0, witness_configured: false }, null)
    expect(steps.map((step) => step.title)).toEqual([
      'Have an outside witness hold your checkpoints',
      'Bind your records to a key you own',
      'Get the other side’s record'
    ])
    expect(steps.map((step) => step.guards)).toEqual([
      'rewrote the record',
      'denying your own records',
      'left something out'
    ])
    expect(steps.map((step) => step.status)).toEqual(['off · your choice', 'not linked', 'none yet'])
    expect(steps[0].body).toMatch(/can only be checked against themselves/)
    expect(steps[1].body).toMatch(/your own claim about who you are, nothing more/)
    expect(steps[0].action).toEqual({ kind: 'link', label: 'Turn on', href: '/configuration/plugins' })
    expect(steps[1].action).toEqual({ kind: 'command', label: 'mesh-llm auth init' })
  })

  it('"Turn on" shows when the witness is off or not reported, as on the Rewrote-the-record card, not when one is on', () => {
    const action = (card: Record<string, unknown> | null) => buildSetupSteps(card, null)[0].action
    expect(action({ checkpoint_count: 1, witness_configured: false })).toMatchObject({ label: 'Turn on' })
    expect(action({ checkpoint_count: 1, witness_configured: true })).toBeUndefined()
    expect(action({ checkpoint_count: 1 })).toMatchObject({ label: 'Turn on' })
    expect(action({ checkpoint_count: 1, witnesses: [{ checked: true }], witness_configured: false })).toBeUndefined()
    expect(action({ checkpoint_count: 1, witness_configured: true, witnessed_checkpoint_count: 0 })).toBeUndefined()
  })

  it('an exchange list that was not read is "not checked", never "none yet"', () => {
    const step = buildSetupSteps({ checkpoint_count: 0 }, null, { total: null, received: 0 })[2]
    expect(step.status).toBe('not checked')
    expect(step.tone).toBe('muted')
    expect(step.done).toBe(false)
    expect(step.body).not.toMatch(/no exchanges yet/)
  })

  it('step 3 is a status carrying its denominator, never a to-do', () => {
    const some = buildSetupSteps({ checkpoint_count: 0 }, null, { total: 4, received: 3 })[2]
    expect(some.status).toBe('3 of 4 received')
    expect(some.done).toBe(false)
    expect(some.body).toBe('Every exchange produces two signed records, one per side. You hold both for 3 of 4.')
    expect(some.action).toEqual({ kind: 'exchanges', label: 'See in Exchanges' })
    expect(`${some.title} ${some.status} ${some.body}`).not.toMatch(/\bask\b/i)

    const all = buildSetupSteps({ checkpoint_count: 0 }, null, { total: 4, received: 4 })[2]
    expect(all.status).toBe('4 of 4 received')
    expect(all.done).toBe(true)
  })

  it('the witness pill says "not checked" when the node did not say whether one is set, never "off"', () => {
    expect(buildSetupSteps(null, null)[0]).toMatchObject({ status: 'not checked', tone: 'muted', done: false })
    expect(buildSetupSteps(null, null)[0].body).toMatch(/did not report its checkpoint status/)
    expect(buildSetupSteps({ checkpoint_count: 2 }, null)[0].status).toBe('not checked')
    expect(buildSetupSteps({ checkpoint_count: 2, witness_configured: true }, null)[0].status).toBe(
      'on · none holds one yet'
    )
  })

  it('D1: a local checkpoint with ZERO witnesses is never "held" — the exact overclaim', () => {
    const steps = buildSetupSteps({ checkpoint_count: 3, witnesses: [], witness_configured: false }, null)
    expect(steps[0].done).toBe(false)
    expect(steps[0].status).toBe('off · your choice')
    expect(steps[0].body).toMatch(/lets someone else prove a rewrite/)
  })

  it('step 1 flips to held ONLY once a witness actually holds a checkpoint, and drops its body and action', () => {
    const steps = buildSetupSteps({ checkpoint_count: 3, witnesses: [{ checked: true }] }, null)
    expect(steps[0]).toMatchObject({ done: true, status: 'held by a witness', body: null, action: undefined })
  })

  it('step 1, the witness line and the Exchanges headline all derive from the ONE checkpointRegistration fact', () => {
    const unwitnessed = { checkpoint_count: 5, witnesses: [] }
    const registration = checkpointRegistration(unwitnessed)
    expect(registration.registered).toBe(false)
    expect(registration.checkpointedLocally).toBe(true)
    expect(buildSetupSteps(unwitnessed, null)[0].done).toBe(false)
    expect(buildRegistrationCopy(unwitnessed)?.witnessSummary).toContain('no witness')

    const witnessed = { checkpoint_count: 5, witnesses: [{ checked: true }] }
    expect(checkpointRegistration(witnessed).registered).toBe(true)
    expect(buildSetupSteps(witnessed, null)[0].status).toBe('held by a witness')
    expect(buildRegistrationCopy(witnessed)?.witnessSummary).toMatch(/^Held by 1 witness/)
  })

  it('step 2 says what binding established once the live owner is verified -- never "bound" alone', () => {
    const steps = buildSetupSteps(null, { status: 'verified', verified: true })
    expect(steps[1].done).toBe(true)
    expect(steps[1].status).toBe('linked (self-asserted)')
    expect(steps[1].action).toBeUndefined()
    expect(steps[1].body).toBe(
      'Your records are signed by this node’s key, linked to your owner account (self-asserted).'
    )
  })

  it('an owner the host did NOT verify is not linked -- every non-verified status the host sends', () => {
    for (const status of ['unsigned', 'expired', 'invalid_signature', 'revoked_owner', 'untrusted_owner']) {
      expect(ownerLinked({ status, verified: false })).toBe(false)
      expect(buildSetupSteps(null, { status, verified: false })[1].status).toBe('not linked')
    }
    expect(ownerLinked({ status: 'verified', verified: true })).toBe(true)
  })

  it('the checks panel binding fact and Integrity step 2 agree from the same owner', () => {
    const binding = (linked: boolean) =>
      buildChecksRows(
        {
          exchange_key: 'e',
          role_tag: 'ASKED',
          header_state: 'ok',
          properties: null,
          has_issue: false,
          mine: { state: 'present', capsule_id: 'm' },
          theirs: { state: 'absent', capsule_id: null },
          unilateral: true,
          timestamp: null
        },
        { idMatch: null, signatureOk: null } as RecomputedIdentity,
        undefined,
        { ownerLinked: linked }
      )
        .find((r) => r.key === 'identity_authority')
        ?.facts?.find((f) => f.factLabel === 'binding')?.cell
    const unsigned = { status: 'unsigned', verified: false }
    expect(buildSetupSteps(null, unsigned)[1].done).toBe(false)
    expect(binding(ownerLinked(unsigned))?.state).not.toBe('PASS')
    const verified = { status: 'verified', verified: true }
    expect(binding(ownerLinked(verified))?.state).toBe('PASS')
    expect(buildSetupSteps(null, verified)[1].body).toContain(binding(ownerLinked(verified))?.detail as string)
  })

  it('step 2 stays not linked when the wire carries no owner at all', () => {
    expect(buildSetupSteps(null, undefined)[1].done).toBe(false)
  })
})

describe('checkpointRegistration — the witness state', () => {
  // The live run's card: a witness set, the latest line a cut no witness
  // holds yet, an earlier one held.
  it('a witness holding an earlier checkpoint is witnessed, never "off"', () => {
    const live = checkpointRegistration({
      checkpoint_count: 3,
      witnesses: [],
      witnessed_checkpoint_count: 1,
      witness_configured: true
    })
    expect(live.registered).toBe(false)
    expect(live.witnessState).toBe('earlier')
    expect(live.witnessedCheckpointCount).toBe(1)
    expect(buildSetupSteps({ checkpoint_count: 3, witnesses: [], witnessed_checkpoint_count: 1 }, null)[0]).toMatchObject({
      done: true,
      status: 'held · not the latest'
    })
  })

  it('reads off, set-but-not-yet and unknown apart', () => {
    const state = (card: Record<string, unknown>) =>
      checkpointRegistration({ checkpoint_count: 1, witnesses: [], ...card }).witnessState
    expect(state({ witness_configured: false })).toBe('off')
    expect(state({ witness_configured: true })).toBe('pending')
    expect(state({})).toBe('unknown')
    expect(state({ witnesses: [{ checked: true }], witness_configured: false })).toBe('latest')
  })
})

describe('witnessCoverageByRecord — each record against the latest checkpoint a witness holds (#411)', () => {
  const at = '2026-11-28T02:00:00Z'
  const ids = ['r1', 'r2', 'r3']
  const witnessedCard = {
    checkpoint_count: 2,
    witnesses: [],
    witnessed_checkpoint_count: 1,
    witness_configured: true,
    // Covers 2 records, counted by the node in records, not leaves.
    latest_witnessed: { timestamp: at, mmr_size: 4, covered_leaf_count: 3, covered_record_count: 2, witnesses: [] }
  }

  it('records the witnessed checkpoint covers are covered; later ones are newer, with its time', () => {
    const coverage = witnessCoverageByRecord(ids, witnessedCard)
    expect(coverage.get('r1')).toEqual({ kind: 'covered', at })
    expect(coverage.get('r2')).toEqual({ kind: 'covered', at })
    expect(coverage.get('r3')).toEqual({ kind: 'newer', at })
  })

  it('compares records, never leaves: padding inside the checkpoint does not cover a later record', () => {
    // 3 leaves (a record, a padding line, a record) but only 1 record before the cut.
    const card = { ...witnessedCard, latest_witnessed: { ...witnessedCard.latest_witnessed, covered_record_count: 1 } }
    expect(witnessCoverageByRecord(ids, card).get('r2')).toEqual({ kind: 'newer', at })
  })

  it('counts in ledger order, never pane A\'s grouping: exchange A, a settlement record, exchange B', () => {
    // Ledger order A, S, B; pane A would list A, B, S. A checkpoint over two
    // records covers A and S, so B is newer.
    const order = ledgerOrderIds([{ capsule_id: 'A' }, { capsule_id: 'S' }, { capsule_id: 'B' }])
    expect(order).toEqual(['A', 'S', 'B'])
    const coverage = witnessCoverageByRecord(order, witnessedCard)
    expect(coverage.get('S')).toEqual({ kind: 'covered', at })
    expect(coverage.get('B')).toEqual({ kind: 'newer', at })
    expect(checkpointCoverageByRecord(order, 2).get('B')).toBe(false)
    // A record with no id keeps its place.
    expect(ledgerOrderIds([{ capsule_id: null }, { capsule_id: 'B' }])).toEqual(['', 'B'])
  })

  it('no witness holds any checkpoint: every record says none', () => {
    const card = { checkpoint_count: 2, witnesses: [], witnessed_checkpoint_count: 0, witness_configured: true }
    expect(witnessCoverageByRecord(ids, card).get('r1')).toEqual({ kind: 'none' })
    expect(witnessCoverageByRecord(ids, { checkpoint_count: 2, witnesses: [] }).get('r1')).toEqual({ kind: 'none' })
  })

  it('unknown stays unknown: witness off, no card, or a witnessed checkpoint with no reported coverage', () => {
    expect(witnessCoverageByRecord(ids, { checkpoint_count: 2, witnesses: [], witness_configured: false }).size).toBe(0)
    expect(witnessCoverageByRecord(ids, null).size).toBe(0)
    const unreported = { ...witnessedCard, latest_witnessed: { timestamp: at, mmr_size: 4, witnesses: [] } }
    expect(latestWitnessed(unreported)).toBeNull()
    expect(witnessCoverageByRecord(ids, unreported).size).toBe(0)
  })

  it('each state reads as Sherlock2\'s line, the time in the viewer\'s zone, named', () => {
    const time = formatExchangeTimestamp(at)
    expect(witnessCoverageLine({ kind: 'covered', at })).toBe(
      `Held by a witness you don’t run: a checkpoint from ${time} includes this record, by this node’s count. This page hasn’t checked with the witness itself.`
    )
    expect(witnessCoverageLine({ kind: 'newer', at })).toBe(
      `Not yet: this record is newer than the last checkpoint a witness you don’t run holds (${time}).`
    )
    expect(witnessCoverageLine({ kind: 'none' })).toBe('Not yet: no witness you don’t run holds a checkpoint from this node.')
  })
})

describe('buildRegistrationCopy — only renders once a checkpoint exists', () => {
  it('is null when no checkpoint exists', () => {
    expect(buildRegistrationCopy(null)).toBeNull()
    expect(buildRegistrationCopy({ checkpoint_count: 0 })).toBeNull()
    expect(buildRegistrationCopy({ checkpoint_count: null })).toBeNull()
  })

  it('renders "Held by N witnesses: <names> (M not operated by this node)"', () => {
    const copy = buildRegistrationCopy({
      checkpoint_count: 2,
      witnesses: [
        { ts_url: 'https://a.example/log', operated_by_producer: true, checked: true },
        { ts_url: 'https://b.example', operated_by_producer: false, checked: true },
        { ts_url: 'https://c.example', checked: true }
      ]
    })
    expect(copy).not.toBeNull()
    expect(copy?.witnessSummary).toBe('Held by 3 witnesses: a.example, b.example, c.example (2 not operated by this node)')
  })

  it('a receipt that did not check is not counted, and never says "held"', () => {
    const card = {
      checkpoint_count: 2,
      witness_configured: true,
      witnesses: [{ ts_url: 'https://a.example', checked: false, check: 'the receipt does not verify' }]
    }
    expect(checkpointRegistration(card).registered).toBe(false)
    expect(checkpointRegistration(card).witnessState).toBe('pending')
    expect(buildRegistrationCopy(card)?.witnessSummary).not.toMatch(/Held by/)
  })

  it('lists every witness by name with what it holds', () => {
    const rows = witnessRows({
      witness_status: [
        { name: 'a.example', url: 'https://a.example', state: 'latest', held_count: 3, checked_count: 3, key_source: 'configured' },
        { name: 'b.example', url: 'https://b.example', state: 'pending', held_count: 0, checked_count: 0, problem: 'refused the connection' },
        { name: 'c.example', url: 'https://c.example', state: 'unchecked', held_count: 1, checked_count: 0, problem: 'its key is not fetched yet' },
        { name: 'd.example', url: 'https://d.example', state: 'earlier', held_count: 2, checked_count: 2, key_source: 'pinned_on_first_contact' }
      ]
    })
    expect(rows.map((row) => [row.name, row.status, row.tone])).toEqual([
      ['a.example', 'holds the latest checkpoint', 'good'],
      ['b.example', 'none held yet', 'pending'],
      ['c.example', '1 receipt not checked', 'bad'],
      ['d.example', 'holds an earlier checkpoint', 'good']
    ])
    expect(rows[1].detail).toBe('refused the connection')
    expect(rows[2].detail).toBe('its key is not fetched yet')
    expect(rows.map((row) => row.key)).toEqual([
      'key configured',
      null,
      null,
      'key taken from its first answer, not configured'
    ])
    expect(witnessRows({})).toEqual([])
  })

  it('a witness with no operated_by_producer field counts toward M (errs independent-claim-is-wrong)', () => {
    const copy = buildRegistrationCopy({ checkpoint_count: 1, witnesses: [{ ts_url: 'https://w.example', checked: true }] })
    expect(copy?.witnessSummary).toBe('Held by 1 witness: w.example (1 not operated by this node)')
  })

  it('D1: an unwitnessed checkpoint reads "checkpointed locally", NEVER "Held by 0 witnesses"', () => {
    const copy = buildRegistrationCopy({ checkpoint_count: 2, witnesses: [], witness_configured: false })
    expect(copy?.witnessSummary).toBe('Checkpointed locally · no witness (witness: off)')
    expect(copy?.witnessSummary).not.toMatch(/Held by 0/)
  })

  it('says "witness: off" only when no witness is set', () => {
    const summary = (card: Record<string, unknown>) =>
      buildRegistrationCopy({ checkpoint_count: 3, witnesses: [], ...card })?.witnessSummary
    expect(summary({ witnessed_checkpoint_count: 1, witness_configured: true })).toBe(
      'Latest checkpoint not held by a witness yet · an earlier one is'
    )
    expect(summary({ witnessed_checkpoint_count: 0, witness_configured: true })).toBe(
      'Checkpointed locally · no witness holds it yet (witness: on)'
    )
    expect(summary({})).toBe('Checkpointed locally · no witness')
  })

  it('adds "witnessed no later than T" (local time) only when a witness holds the checkpoint; unwitnessed says "checkpointed no later than"', () => {
    const registered = buildRegistrationCopy({
      checkpoint_count: 1,
      witnesses: [{ checked: true }],
      registered_no_later_than: '2026-09-10T00:00:00Z'
    })
    const local = formatExchangeTimestamp('2026-09-10T00:00:00Z')
    expect(registered?.registeredNoLaterThan).toBe(`witnessed no later than ${local}`)
    expect(registered?.registeredNoLaterThan).not.toMatch(/T00:00|Z\b/)

    // The card field name is the wire's; the COPY must not overclaim -- an
    // unwitnessed checkpoint's timestamp is a local fact, not a registration.
    const unwitnessed = buildRegistrationCopy({
      checkpoint_count: 1,
      witnesses: [],
      registered_no_later_than: '2026-09-10T00:00:00Z'
    })
    expect(unwitnessed?.registeredNoLaterThan).toBe(`checkpointed no later than ${local}`)

    const withoutDate = buildRegistrationCopy({ checkpoint_count: 1, witnesses: [] })
    expect(withoutDate?.registeredNoLaterThan).toBeNull()
  })
})

describe('coveredRecordCount — coverage in records, never padding leaves', () => {
  it('reads the records a checkpoint covers, not its leaf count', () => {
    // 8 leaves covered, of which 6 are padding: 2 records are covered.
    expect(coveredRecordCount({ covered_leaf_count: 8, covered_record_count: 2 })).toBe(2)
  })

  it('is unknown, never the leaf count, when the host reports no record count', () => {
    expect(coveredRecordCount({ covered_leaf_count: 8 })).toBeNull()
    expect(coveredRecordCount(null)).toBeNull()
  })

  it('so a padded checkpoint never reads unsealed records as sealed', () => {
    const covered = coveredRecordCount({ covered_leaf_count: 8, covered_record_count: 2 })
    expect(coverageBadge(3, 1, covered)).toBe('2 of 3 in a checkpoint')
  })
})

describe('records strip — heading, badge and breakdown, every count with its denominator', () => {
  it('the heading counts sealed records and checkpoints', () => {
    expect(recordsStripHeading(13, 5)).toBe('Your records · 13 sealed · 5 checkpoints')
    expect(recordsStripHeading(1, 1)).toBe('Your records · 1 sealed · 1 checkpoint')
  })

  it('full coverage reads "All N in a checkpoint"; partial says how many of how many', () => {
    expect(coverageBadge(13, 5, 13)).toBe('All 13 in a checkpoint')
    expect(coverageBadge(5, 1, 4)).toBe('4 of 5 in a checkpoint')
    expect(coverageBadge(1, 1, 1)).toBe('1 of 1 in a checkpoint')
  })

  it('says "not checked" where the node reported nothing, never a false "none"', () => {
    expect(recordsStripHeading(2, null)).toBe('Your records · 2 sealed · checkpoints not checked')
    expect(coverageBadge(2, null, null)).toBe('checkpoints not checked')
    expect(coverageBadge(5, 2, null)).toBe('coverage not checked')
    expect(coverageBadge(1, 0, null)).toBe('0 of 1 in a checkpoint')
    expect(coverageBadge(0, 0, null)).toBe('no records yet')
  })

  it('the breakdown adds the last checkpoint time only when the node gave one', () => {
    expect(recordsStripBreakdown(9, 4, 0, 0, null)).toBe('9 yours · 4 received')
    expect(recordsStripBreakdown(9, 4, 0, 0, '2026-09-10T16:28:00Z')).toBe(
      `9 yours · 4 received · last checkpoint no later than ${formatExchangeTimestamp('2026-09-10T16:28:00Z')}`
    )
  })

  it('no strip text uses the word "chain"', () => {
    const texts = [
      recordsStripHeading(3, 1),
      coverageBadge(3, 1, 3),
      recordsStripBreakdown(1, 1, 1, 1, '2026-09-10T16:28:00Z'),
      CHAIN_BAR_INFO
    ]
    expect(texts.join(' ')).not.toMatch(/chain/i)
  })
})

describe('Item 4 — Integrity tile + chain-bar (i) copy: evidence, never a score', () => {
  it('names an evidence source in every tile line and refuses the score reading', () => {
    for (const info of Object.values(INTEGRITY_TILE_INFO)) {
      expect(info.length).toBeGreaterThan(0)
      // UX §8 rule 4: a banned word stays off the screen even to deny it.
      expect(info).not.toMatch(new RegExp(`\\b(score|rating|proven|${STANDING_WORD}|judgement)\\b`, 'i'))
    }
    // The witness tile names the witness; the closed tile names their signed
    // record, checked on this machine.
    expect(INTEGRITY_TILE_INFO.confirmedByOtherSide).toMatch(/their own signed record, checked on this machine/)
  })

  it('the chain-bar (i) carries the checkpoint-coverage explanation (moved off the caption)', () => {
    expect(CHAIN_BAR_INFO).toBe(
      'Shaded: records sealed into a checkpoint. Unshaded: records sealed since the last checkpoint.'
    )
  })
})

describe('once-per-node facts — never fabricated, never per-row', () => {
  it('retention and capture-boundary are stated facts, not data claims', () => {
    expect(RETENTION_FACT).toMatch(/Retention:/)
    expect(CAPTURE_BOUNDARY_FACT).toMatch(/Capture boundary:/)
  })

  it('identity fact renders bound vs. not-bound, always ending "not bound to a person"', () => {
    expect(identityFact(null)).toBe('Owner: not bound — not bound to a person.')
    expect(identityFact({ status: 'verified', verified: true })).toBe(
      'Owner: linked (self-asserted) — not bound to a person.'
    )
  })

  it('continuity default prose names what would establish it: a PRIOR checkpoint, not registration', () => {
    expect(CONTINUITY_NOT_ESTABLISHED).toBe(
      'Continuity: not established. It needs a prior checkpoint for the next one to bind to.'
    )
    expect(CONTINUITY_NOT_ESTABLISHED).not.toMatch(/regist/i)
  })

  it('continuity is stated from the checkpoint count, separately from registration (UX §4)', () => {
    expect(continuityFact(null)).toBe(CONTINUITY_NOT_ESTABLISHED)
    expect(continuityFact(0)).toBe(CONTINUITY_NOT_ESTABLISHED)
    expect(continuityFact(1)).toBe(
      'Continuity: 1 checkpoint so far. The next one builds on it. A witness is what lets someone else check it too.'
    )
    // Never claims each checkpoint binds to the one before -- not reported.
    expect(continuityFact(3)).toBe(
      'Continuity: 3 checkpoints so far. A witness is what lets someone else check them too.'
    )
  })

  it('the Sealed tile reconciles records with exchanges (finding 3)', () => {
    expect(sealedBreakdownText(5, 3)).toBe('5 yours · 3 received')
    // A block and its undo are sealed, counted apart from exchanges.
    expect(sealedBreakdownText(5, 3, 2)).toBe('5 yours · 3 received · 2 routing choices')
    expect(sealedBreakdownText(5, 3, 1)).toBe('5 yours · 3 received · 1 routing choice')
  })
})

describe('banned vocabulary — never "timestamped", never "registered", and "witnessed" only when a witness holds it', () => {
  const allStrings = [
    RETENTION_FACT,
    CAPTURE_BOUNDARY_FACT,
    CONTINUITY_NOT_ESTABLISHED,
    identityFact(null),
    identityFact({ status: 'verified', verified: true }),
    ...buildSetupSteps(null, null).flatMap((step) => [step.title, step.status, step.body ?? '']),
    ...buildSetupSteps({ checkpoint_count: 1 }, { verified: true }).flatMap((step) => [
      step.title,
      step.status,
      step.body ?? ''
    ]),
    buildRegistrationCopy({ checkpoint_count: 1, witnesses: [{ checked: true }] })?.witnessSummary ?? ''
  ]

  it('never renders "timestamped"', () => {
    for (const text of allStrings) expect(text.toLowerCase()).not.toMatch(/timestamped/)
  })

  it('never renders "registered" (UX: jargon; the plain word is "witnessed")', () => {
    for (const text of allStrings) expect(text.toLowerCase()).not.toMatch(/\bregistered\b/)
  })

  it('says "witnessed" only when a witness holds a checkpoint, never for a local one', () => {
    const unwitnessed = { checkpoint_count: 1, witnesses: [], registered_no_later_than: '2026-09-10T00:00:00Z' }
    const local = [
      ...buildSetupSteps(unwitnessed, null).flatMap((step) => [step.title, step.status, step.body ?? '']),
      buildRegistrationCopy(unwitnessed)?.witnessSummary ?? '',
      buildRegistrationCopy(unwitnessed)?.registeredNoLaterThan ?? ''
    ]
    for (const text of local) expect(text.toLowerCase()).not.toMatch(/\bwitnessed\b/)
  })
})

describe('the witness list says when saved changes are not in force yet', () => {
  it('notes a restart only when the saved list differs from the one in use', () => {
    expect(witnessRestartNote({ witness_restart_needed: true })).toMatch(/takes effect when mesh-llm restarts/)
    expect(witnessRestartNote({ witness_restart_needed: false })).toBeNull()
    expect(witnessRestartNote({})).toBeNull()
  })
})

describe('configured witness key problems are shown', () => {
  it('lists each problem string, and nothing without any', () => {
    expect(witnessKeyProblems({ witness_key_problems: ['bad key'] })).toEqual(['bad key'])
    expect(witnessKeyProblems({})).toEqual([])
  })
})
