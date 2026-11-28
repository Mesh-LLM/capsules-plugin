// Honesty-backbone invariants for the Peers tab (
// ): with-you/their-chain facts are never
// summed, adjudications always carry a denominator, NOT_CHECKED never
// renders as a silent corroborated pass, and the new accountability columns
// (confirmed-by-other-side, match, period) never invent a fraction the
// sidecar doesn't back. These are the properties an adversarial reviewer
// would try to break, so they're asserted directly against the pure
// view-model functions rather than only through component snapshots.
import { ed25519 } from '@noble/curves/ed25519'
import { describe, expect, it } from 'vitest'
import { hex, signedBy } from '@/features/capsules/lib/cose-test-signing'
import type { PaneBConfirmedSibling, PaneBRow, PaneCRow, TwinRowFacts } from '@/features/capsules/api/sidecarTypes'
import { LatencySource } from '@/lib/api/types'
import type { PeerMeshStatus } from '@/features/capsules/lib/peer-mesh-status'
import {
  adjudicationSummary,
  adjudicationSummaryText,
  alarmSignal,
  confirmedByOtherSide,
  dealtWithRowView,
  isUnattributedPeerRow,
  matchTally,
  meshMetaLine,
  peerAliasLine,
  unlinkedNodeId,
  peerDisplayId,
  peerFacts,
  periodRangeText,
  peerSortKey,
  PEER_COLUMN_INFO,
  sortPeerRows,
  unattributedExchangesLine,
  withYouCounts,
  withYouCountsText
} from '@/features/capsules/lib/peer-row-view'
import { fixtureMineCell, fixtureTheirsCell } from '@/features/capsules/lib/pushed-half-fixtures'
import { STANDING_WORD } from '@/features/capsules/lib/banned-terms'

function baseRow(overrides: Partial<PaneBRow> = {}): PaneBRow {
  return {
    peer_id: 'node:test-peer',
    node: { state: 'present', text: 'node:test-peer' },
    rung: { state: 'present', text: 'full_bilateral', rung: 'full_bilateral' },
    role: { state: 'present', text: '', role: 'both', you_to_them_count: 0, them_to_you_count: 0, exchange_count: 0 },
    history: { state: 'NOT_CHECKED', text: null },
    served: { state: 'NOT_CHECKED', text: null },
    pair: { state: 'absent', text: null, verified: 0, failed: 0, missing: 0, details: [] },
    verdicts: { state: 'NOT_CHECKED', text: null, tally: { corroborated: 0, contradicted: 0, inconclusive: 0 } },
    asked: { state: 'absent', text: null, count: 0 },
    exchange_count: 0,
    first_seen: null,
    last_seen: null,
    ...overrides
  }
}

/** A pushed counterparty half as the Rust pane supplies it: both bodies, the
 *  door's verdict and the browser's id recompute. `verified` -> the bodies
 *  agree (closes); `failed` -> a digest differs (contradicts); `absent` -> the
 *  pushed body carries no digests to compare (not confirmed). Same builders as
 *  the Pane C fixtures so the two panes are pinned against the SAME gate. */
function confirmedSibling(
  overrides: Partial<PaneBConfirmedSibling['theirs']> & { matchState?: 'verified' | 'failed' | 'absent' } = {}
): PaneBConfirmedSibling {
  const { matchState = 'verified', ...theirs } = overrides
  const base = fixtureTheirsCell(matchState === 'failed' ? 'disagrees' : 'agrees', { receivedFrom: 'node:node-a' })
  if (matchState === 'absent' && base.record) {
    const { effect: _noDigests, ...record } = base.record
    base.record = record
  }
  return {
    mine: fixtureMineCell(),
    theirs: { ...base, ...theirs },
    digest_match: { state: matchState }
  }
}

// #412: Pane B runs the same gate on a sibling of an exchange this node
// SERVED, so it counts the requester's record only when the requester's
// announced key signed it -- the same answer Pane C gives for that exchange.
describe('confirmedByOtherSide — a served exchange needs the requester’s signature (#412)', () => {
  const REQUESTER = ed25519.utils.randomSecretKey()
  const OTHER_NODE = ed25519.utils.randomSecretKey()
  const REQUESTER_KEY = hex(ed25519.getPublicKey(REQUESTER))

  function servedSibling(signer: Uint8Array, requesterKeyId: string | null): PaneBConfirmedSibling {
    const sibling = confirmedSibling()
    const record = signedBy(sibling.theirs.record ?? {}, signer)
    return {
      ...sibling,
      mine: { ...fixtureMineCell(), role: 'served', requester_key_id: requesterKeyId },
      theirs: { ...sibling.theirs, role: 'requested', record }
    }
  }

  it('counts one signed by the requester’s announced key', () => {
    const row = baseRow({ exchange_count: 1, confirmed_siblings: [servedSibling(REQUESTER, REQUESTER_KEY)] })
    expect(confirmedByOtherSide(row).confirmed).toBe(1)
  })

  it('does not count one signed by another node’s key, nor any when the requester announced none', () => {
    const row = baseRow({
      exchange_count: 2,
      confirmed_siblings: [servedSibling(OTHER_NODE, REQUESTER_KEY), servedSibling(REQUESTER, null)]
    })
    expect(confirmedByOtherSide(row)).toEqual({ confirmed: 0, total: 2, note: 'none confirmed yet' })
  })
})

describe('withYouCounts — fold-in finding 1: confirmed comes from the ONE gate', () => {
  it('reads requested/served from role_and_count_cell and confirmed from the gate — NEVER pair.verified', () => {
    const row = baseRow({
      role: {
        state: 'present',
        text: '',
        role: 'both',
        you_to_them_count: 24,
        them_to_you_count: 12,
        exchange_count: 36
      },
      // ADVERSARIAL: pair.verified says 20, but no native payload populates
      // it (always 0 live) -- the inspector Overview must not read it. The
      // gate closes exactly the two siblings below.
      pair: { state: 'verified', text: '', verified: 20, failed: 0, missing: 0, details: [] },
      confirmed_siblings: [confirmedSibling(), confirmedSibling()]
    })
    expect(withYouCounts(row)).toEqual({ requested: 24, served: 12, confirmed: 2 })
    expect(withYouCountsText(withYouCounts(row))).toBe('24 requested · 12 served · 2 saved as confirmed')
  })

  it('PINNED: the inspector Overview count equals the Peers table count — one predicate, one number, two surfaces', () => {
    const rows = [
      baseRow({ exchange_count: 6, confirmed_siblings: [confirmedSibling(), confirmedSibling(), confirmedSibling()] }),
      baseRow({ exchange_count: 2, confirmed_siblings: [] }),
      baseRow({
        exchange_count: 4,
        confirmed_siblings: [confirmedSibling(), confirmedSibling({ matchState: 'failed' })]
      })
    ]
    for (const row of rows) {
      expect(withYouCounts(row).confirmed).toBe(confirmedByOtherSide(row).confirmed)
    }
  })
})

describe('adjudicationSummary honesty invariants', () => {
  it('never summarizes a NOT_CHECKED verdicts cell as corroborated, even with a nonzero exchange_count', () => {
    const row = baseRow({
      exchange_count: 24,
      verdicts: { state: 'NOT_CHECKED', text: null, tally: { corroborated: 0, contradicted: 0, inconclusive: 0 } }
    })
    const summary = adjudicationSummary(row)
    expect(summary.notChecked).toBe(true)
    const text = adjudicationSummaryText(summary)
    expect(text).not.toMatch(/corroborated/)
    expect(text.toLowerCase()).toContain('not yet checked')
  })

  it('always carries the exchange_count denominator alongside a real tally, compact form matches the full form', () => {
    const row = baseRow({
      exchange_count: 24,
      verdicts: { state: 'present', text: '', tally: { corroborated: 8, contradicted: 0, inconclusive: 0 } }
    })
    const summary = adjudicationSummary(row)
    expect(summary).toEqual({
      checked: 8,
      denominator: 24,
      corroborated: 8,
      contradicted: 0,
      inconclusive: 0,
      notChecked: false
    })
    expect(adjudicationSummaryText(summary)).toBe('8 of 24 adjudicated · 8 corroborated')
  })

  it('never drops a contradicted/inconclusive count out of either the full or compact summary text', () => {
    const row = baseRow({
      exchange_count: 14,
      verdicts: { state: 'contradicted', text: '', tally: { corroborated: 6, contradicted: 1, inconclusive: 2 } }
    })
    const summary = adjudicationSummary(row)
    expect(adjudicationSummaryText(summary)).toBe(
      '9 of 14 adjudicated · 6 corroborated · 1 contradicted · 2 inconclusive'
    )
  })

  it('treats an all-zero tally as not-checked even if the cell state claims "present"', () => {
    // Defends against a future backend regression where a present-but-empty
    // tally could otherwise read as "0 corroborated" (which looks like a
    // clean bill, not "nothing was checked").
    const row = baseRow({
      exchange_count: 5,
      verdicts: { state: 'present', text: '', tally: { corroborated: 0, contradicted: 0, inconclusive: 0 } }
    })
    expect(adjudicationSummary(row).notChecked).toBe(true)
  })
})

describe('confirmedByOtherSide — routed through the ONE gate, the same predicate Pane C uses', () => {
  it('states "none received yet" as a fact (never "pending" work) when no half has arrived from the other side', () => {
    const row = baseRow({ exchange_count: 11, confirmed_siblings: [] })
    const summary = confirmedByOtherSide(row)
    expect(summary).toEqual({ confirmed: 0, total: 11, note: 'none confirmed yet' })
    // ADVERSARIAL: never resurrect the retired browser-peer-fetch framing.
  })

  it('counts a half confirmed only when the ONE gate closes it (signature_ok + verified digest_match) -- never a fetch predicate', () => {
    const row = baseRow({
      exchange_count: 3,
      confirmed_siblings: [confirmedSibling(), confirmedSibling(), confirmedSibling()]
    })
    const summary = confirmedByOtherSide(row)
    expect(summary).toEqual({ confirmed: 3, total: 3, note: null })
  })

  it('denominator is the DISTINCT-exchange count, so 3 confirmed exchanges read "3 of 3", never "3 of 6"', () => {
    // The host now sends exchange_count as the distinct-exchange count
    // (`distinct_exchange_count` in capsule_panes_native.rs), NOT the record
    // count -- 3 exchanges, whose 6 halves would have read "3 of 6" off a
    // record count. The peer-row view reads that field verbatim for both the
    // Exchanges cell and the Confirmed denominator, so both track the fix.
    const row = baseRow({
      exchange_count: 3,
      confirmed_siblings: [confirmedSibling(), confirmedSibling(), confirmedSibling()]
    })
    expect(dealtWithRowView(row).exchangeCount).toBe(3)
    expect(dealtWithRowView(row).facts.leftOut).toMatchObject({ matched: 3, total: 3 })
  })

  it('never closes a sibling the gate does not close (no signature, or no digest match)', () => {
    const row = baseRow({
      exchange_count: 2,
      confirmed_siblings: [confirmedSibling({ signature_ok: false }), confirmedSibling({ matchState: 'absent' })]
    })
    expect(confirmedByOtherSide(row)).toEqual({ confirmed: 0, total: 2, note: 'none confirmed yet' })
  })

  it('names a contradicted half distinctly, so the count and the alarm can never diverge', () => {
    const row = baseRow({
      exchange_count: 4,
      confirmed_siblings: [confirmedSibling(), confirmedSibling({ matchState: 'failed' })]
    })
    const summary = confirmedByOtherSide(row)
    expect(summary).toEqual({ confirmed: 1, total: 4, note: '1 contradicted' })
  })
})

describe('matchTally — clean/mismatch of the halves the other side sent, via the SAME ONE gate', () => {
  it('always shows clean/mismatch even at zero, omits contradicted when zero', () => {
    const row = baseRow({ confirmed_siblings: Array.from({ length: 11 }, () => confirmedSibling()) })
    expect(matchTally(row)).toEqual({ clean: 11, mismatch: 0, contradicted: 0 })
  })

  it('counts a gate-contradicted sibling as a mismatch, and appends the adjudication contradicted count when nonzero', () => {
    const row = baseRow({
      confirmed_siblings: [
        ...Array.from({ length: 9 }, () => confirmedSibling()),
        confirmedSibling({ matchState: 'failed' })
      ],
      verdicts: { state: 'contradicted', text: '', tally: { corroborated: 6, contradicted: 1, inconclusive: 0 } }
    })
    expect(matchTally(row)).toEqual({ clean: 9, mismatch: 1, contradicted: 1 })
  })

  it('counts halves the door refused on their claims as differing, so Peers matches the hero', () => {
    const row = baseRow({
      confirmed_siblings: Array.from({ length: 3 }, () => confirmedSibling()),
      claims_refused: 2
    })
    expect(matchTally(row)).toMatchObject({ clean: 3, mismatch: 2 })
  })
})

describe('periodRangeText', () => {
  it('is "—" with no exchange history to bound', () => {
    expect(periodRangeText(null, null)).toBe('—')
  })

  it('compresses a same-month range to "D–D Mon"', () => {
    expect(periodRangeText('2026-09-22T00:00:00Z', '2026-09-23T00:00:00Z')).toBe('22–23 Sep')
  })

  it('spells out both months when the range crosses a month boundary', () => {
    expect(periodRangeText('2026-08-20T09:12:00Z', '2026-09-08T16:58:05Z')).toBe('20 Aug – 8 Sep')
  })

  it('spells out both years when the range crosses a year boundary', () => {
    expect(periodRangeText('2025-12-30T00:00:00Z', '2026-01-02T00:00:00Z')).toBe('30 Dec 2025 – 2 Jan 2026')
  })
})

describe('alarmSignal', () => {
  it('surfaces a contradiction with a resolved date when the ledger has it', () => {
    const row = baseRow({
      verdicts: {
        state: 'contradicted',
        text: '',
        tally: { corroborated: 6, contradicted: 1, inconclusive: 0 },
        adjudication_capsule_id: 'cap-0007'
      }
    })
    const alarm = alarmSignal(row, (id) => (id === 'cap-0007' ? '2026-09-01' : null))
    expect(alarm).toEqual({ present: true, text: 'Contradiction found 2026-09-01', tone: 'bad' })
  })

  it('never fabricates a date when the local ledger has no matching record', () => {
    const row = baseRow({
      verdicts: {
        state: 'contradicted',
        text: '',
        tally: { corroborated: 0, contradicted: 1, inconclusive: 0 },
        adjudication_capsule_id: 'cap-unknown'
      }
    })
    const alarm = alarmSignal(row, () => null)
    expect(alarm.text).toBe('Contradiction found')
  })

  it('is absent for a clean row', () => {
    expect(alarmSignal(baseRow()).present).toBe(false)
  })
})

describe('sortPeerRows', () => {
  it('floats an alarmed row above a lower-latency clean row', () => {
    const clean = baseRow({ peer_id: 'clean' })
    const alarmed = baseRow({
      peer_id: 'alarmed',
      verdicts: { state: 'contradicted', text: '', tally: { corroborated: 0, contradicted: 1, inconclusive: 0 } }
    })
    const sorted = sortPeerRows(
      [
        { row: clean, latencyMs: 10 },
        { row: alarmed, latencyMs: 500 }
      ],
      ({ row, latencyMs }) => peerSortKey(row, latencyMs)
    )
    expect(sorted.map((entry) => entry.row.peer_id)).toEqual(['alarmed', 'clean'])
  })

  it('sorts two clean rows closest-first by latency', () => {
    const near = baseRow({ peer_id: 'near' })
    const far = baseRow({ peer_id: 'far' })
    const sorted = sortPeerRows(
      [
        { row: far, latencyMs: 200 },
        { row: near, latencyMs: 5 }
      ],
      ({ row, latencyMs }) => peerSortKey(row, latencyMs)
    )
    expect(sorted.map((entry) => entry.row.peer_id)).toEqual(['near', 'far'])
  })
})

describe('peerDisplayId — no synthetic peer', () => {
  it('ADVERSARIAL: never returns the string "unknown peer" — a row with no identity resolves to null', () => {
    const row = baseRow({ peer_id: null, node: { state: 'present', text: null } })
    expect(peerDisplayId(row)).toBeNull()
    expect(peerDisplayId(row)).not.toBe('unknown peer')
    expect(isUnattributedPeerRow(row)).toBe(true)
  })

  it('falls back to the node cell id when the row-level peer_id is absent', () => {
    const row = baseRow({ peer_id: null, node: { state: 'present', text: null, peer_id: 'node:aa11bb22cc33' } })
    expect(peerDisplayId(row)).toBe('node:aa11bb22cc33')
    expect(isUnattributedPeerRow(row)).toBe(false)
  })

  it('prefers the row-level peer_id over the node cell id when both are present', () => {
    const row = baseRow({ peer_id: 'peer-verified', node: { state: 'present', text: null, peer_id: 'node:other' } })
    expect(peerDisplayId(row)).toBe('peer-verified')
  })
})

describe('peerAliasLine — D3: aliases on ONE row, never extra peers', () => {
  it('renders "signed by <key16> · endpoint <id>" for a key-joined peer with no node evidence', () => {
    const row = baseRow({
      peer_id: 'key:71eb777777777777',
      identity: {
        signing_key_id: '71eb777777777777777777777777777777777777777777777777777777777777',
        endpoint_id: 'e5ba9d1001',
        node_id: null
      }
    })
    expect(peerAliasLine(row)).toBe('signed by 71eb777777777777 · endpoint e5ba9d1001')
  })

  it('never puts a 64-hex endpoint id on the row face: 16 characters and an ellipsis', () => {
    const endpoint = 'c6839699559fd005'.repeat(4)
    const row = baseRow({
      peer_id: 'key:71eb777777777777',
      identity: {
        signing_key_id: '71eb777777777777777777777777777777777777777777777777777777777777',
        endpoint_id: endpoint,
        node_id: null
      }
    })
    expect(peerAliasLine(row)).toBe('signed by 71eb777777777777 · endpoint c6839699559fd005…')
    expect(peerAliasLine(row)).not.toMatch(/[0-9a-f]{64}/)
  })

  it('adds the node alias only when the evidence carries one (the bridged case)', () => {
    const row = baseRow({
      peer_id: 'key:71eb777777777777',
      identity: {
        signing_key_id: '71eb777777777777777777777777777777777777777777777777777777777777',
        endpoint_id: 'e5ba9d1001',
        node_id: `a70d3967bea3b22f${'a'.repeat(48)}`
      }
    })
    expect(peerAliasLine(row)).toBe('signed by 71eb777777777777 · node a70d3967bea3b22f… · endpoint e5ba9d1001')
  })

  it('labels the UNLINKED node-id row honestly — known from our own records, no signed record from them yet', () => {
    const row = baseRow({
      peer_id: 'node:a70d3967bea3b22f',
      identity: { signing_key_id: null, endpoint_id: null, node_id: `a70d3967bea3b22f${'a'.repeat(48)}` }
    })
    expect(unlinkedNodeId(row)).toBe(`a70d3967bea3b22f${'a'.repeat(48)}`)
    expect(peerAliasLine(row)).toBe('Known from your records · no signed record from them yet')
    // A key this node knows for that node (host-announced or configured): the
    // row names it, claiming no source, never "no signing key linked".
    expect(peerAliasLine(row, 'e'.repeat(64))).toBe(
      `Known from your records · its signing key ${'e'.repeat(16)} is known to this node`
    )
    expect(dealtWithRowView(row, undefined, [], 'e'.repeat(64)).aliasLine).toContain('is known to this node')
  })

  it('degrades to null (no line, never a fabricated identity) when the row carries no identity evidence', () => {
    expect(peerAliasLine(baseRow())).toBeNull()
    expect(peerAliasLine(baseRow({ identity: null }))).toBeNull()
  })

  it('the dealt-with view carries the alias line', () => {
    const row = baseRow({
      identity: { signing_key_id: 'ab'.repeat(32), endpoint_id: 'e5ba9d1001', node_id: null }
    })
    expect(dealtWithRowView(row).aliasLine).toBe(`signed by ${'ab'.repeat(8)} · endpoint e5ba9d1001`)
  })
})

describe('unattributedExchangesLine', () => {
  it('states the count as a fact, never implying pending work', () => {
    expect(unattributedExchangesLine(3)).toBe(
      '3 exchanges have no other side recorded yet. They appear under Exchanges.'
    )
    expect(unattributedExchangesLine(3)).not.toMatch(/not resolved yet/i)
  })

  it('uses singular grammar for a count of one', () => {
    expect(unattributedExchangesLine(1)).toBe(
      '1 exchange has no other side recorded yet. They appear under Exchanges.'
    )
  })
})

describe('meshMetaLine — still used by the PeerInspector modal', () => {
  function meshStatus(overrides: Partial<PeerMeshStatus> = {}): PeerMeshStatus {
    return {
      modelName: 'Qwen3.6-27B-UD',
      quant: 'Q4_K_XL',
      contextLengthK: 256,
      latencyMs: 38,
      latencySource: LatencySource.DIRECT,
      online: true,
      ...overrides
    }
  }

  it('joins model/quant/context', () => {
    expect(meshMetaLine(meshStatus())).toBe('Qwen3.6-27B-UD · Q4_K_XL · 256k ctx')
  })

  it('degrades to null (never a fabricated line) when nothing is known', () => {
    expect(meshMetaLine(null)).toBeNull()
  })
})

describe('dealtWithRowView — honest degradation', () => {
  it('a dealt-with row carries the real Pane B row, exchange count, and every accountability column', () => {
    const row = baseRow({
      peer_id: 'node:abc',
      confirmed_siblings: Array.from({ length: 16 }, () => confirmedSibling()),
      exchange_count: 24,
      first_seen: '2026-09-01T00:00:00Z',
      last_seen: '2026-09-03T00:00:00Z',
      verdicts: { state: 'present', text: '', tally: { corroborated: 8, contradicted: 0, inconclusive: 0 } }
    })
    const view = dealtWithRowView(row)
    expect(view.row).toBe(row)
    expect(view.exchangeCount).toBe(24)
    expect(view.period).toBe('3 Sep')
    // 16 halves closed through the gate, 24 exchanges total.
    expect(view.facts.leftOut.text).toBe('16/24 matched')
  })

  it('no accountability figure on a view ever renders a percentage or ratio ramp (R-D)', () => {
    const row = baseRow({
      exchange_count: 24,
      verdicts: { state: 'present', text: '', tally: { corroborated: 8, contradicted: 0, inconclusive: 0 } }
    })
    const view = dealtWithRowView(row)
    for (const text of [
      view.period,
      view.facts.rewrote.text,
      view.facts.leftOut.text,
      view.facts.swapped.text,
      view.facts.swapped.tally
    ]) {
      expect(text).not.toContain('%')
    }
  })
})

describe('Item 4 — Peers column (i) copy: evidence, never a score', () => {
  it('Left something out says what it counts, out of how many', () => {
    expect(PEER_COLUMN_INFO.leftOut).toContain('same request, answer and model as yours')
    expect(PEER_COLUMN_INFO.leftOut).toContain('out of all your exchanges with them')
  })

  it('Their records witnessed is no column any more', () => {
    expect(Object.keys(PEER_COLUMN_INFO)).toEqual(['exchanges', 'rewrote', 'leftOut', 'swapped', 'period'])
  })

  it('every column line names what it means / what backs it and refuses the score reading', () => {
    for (const key of ['exchanges', 'rewrote', 'leftOut', 'swapped', 'period'] as const) {
      const info = PEER_COLUMN_INFO[key]
      expect(info.length).toBeGreaterThan(0)
      expect(info).not.toMatch(new RegExp(`\\b(score|rating|proven|${STANDING_WORD}|judgement|ranking)\\b`, 'i'))
    }
  })
})

// ---------------------------------------------------------------------------
// The three ways a stranger could cheat, per peer (`peerFacts`).
// ---------------------------------------------------------------------------

/** One row of a twin pair, as pane C carries it: this node asked `counterparty`. */
function pairRow(key: string, counterparty: string, twin: Partial<TwinRowFacts> & { bracket_id: string }): PaneCRow {
  return {
    exchange_key: key,
    role_tag: 'ASKED',
    counterparty,
    header_state: 'ok',
    properties: null,
    has_issue: false,
    mine: { state: 'present', capsule_id: `${key}-mine` },
    theirs: { state: 'present', capsule_id: `${key}-theirs` },
    unilateral: false,
    timestamp: '2026-10-30T16:17:00Z',
    twin_bracket_id: twin.bracket_id,
    twin: { same_answer: null, other_row: null, ...twin }
  }
}

/** A pair `a` and `b` were asked; the referee this node asked ruled `verdict`. */
function askedPair(n: number, a: string, b: string, verdict: string, referee = 'node:ref'): PaneCRow[] {
  const referee_row = { state: 'adjudicated' as const, verdict, referee, tier: 1 }
  return [
    pairRow(`a${n}`, a, { bracket_id: `b${n}`, other_row: `b${n}x`, referee_row }),
    pairRow(`b${n}x`, b, { bracket_id: `b${n}`, other_row: `a${n}`, referee_row })
  ]
}

const SWAP_PEER = baseRow({
  peer_id: 'peer:swap',
  identity: { signing_key_id: 'ab'.repeat(32), endpoint_id: null, node_id: 'node:swap-node' },
  exchange_count: 3
})

describe('peerFacts — rewrote the record', () => {
  it('reads Sealed for a peer with exchanges on your record, and not checked for none', () => {
    expect(peerFacts(baseRow({ exchange_count: 2 })).rewrote).toEqual({ text: 'Sealed', tone: 'good' })
    expect(peerFacts(baseRow({ exchange_count: 0 })).rewrote.text).toBe('not checked')
  })
})

describe('peerFacts — left something out', () => {
  it('shows n/m matched with the denominator, from the records the gate closed', () => {
    const row = baseRow({
      exchange_count: 4,
      confirmed_siblings: [confirmedSibling(), confirmedSibling()]
    })
    expect(peerFacts(row).leftOut).toMatchObject({ text: '2/4 matched', matched: 2, total: 4 })
  })

  it('names a differing record instead of a clean count', () => {
    const row = baseRow({ exchange_count: 2, claims_refused: 1 })
    expect(peerFacts(row).leftOut).toMatchObject({ text: '1 of 2 differ', tone: 'bad' })
  })

  it('reads not checked with no exchanges, never 0 / 0', () => {
    expect(peerFacts(baseRow()).leftOut.text).toBe('not checked')
  })
})

describe('peerFacts — swapped the model counts only referee verdicts this node asked for', () => {
  it('is Not tested, reading "not checked", when no referee was asked', () => {
    const facts = peerFacts(SWAP_PEER, [])
    expect(facts.swapped).toMatchObject({ text: 'Not tested', tone: 'muted', checked: 0, tally: 'not checked' })
  })

  it('a verdict contradicting this peer is Contradicted by referee, with its denominator', () => {
    const rows = [
      ...askedPair(1, 'peer:swap', 'peer:other', 'contradicted:node:swap-node'),
      ...askedPair(2, 'peer:swap', 'peer:other', 'corroborated'),
      ...askedPair(3, 'peer:swap', 'peer:other', 'inconclusive')
    ]
    const { swapped } = peerFacts(SWAP_PEER, rows)
    expect(swapped).toMatchObject({ text: 'Contradicted by referee', tone: 'bad', caught: 1, checked: 3 })
    expect(swapped.tally).toBe('1 caught · 3 checked')
    expect(swapped.otherNode).toBe('peer:other')
    expect(swapped.referee).toBe('node:ref')
  })

  it('a verdict contradicting the OTHER machine corroborates this peer', () => {
    const rows = askedPair(1, 'peer:swap', 'peer:other', 'contradicted:peer:other')
    expect(peerFacts(SWAP_PEER, rows).swapped).toMatchObject({
      text: 'Corroborated by referee',
      tone: 'good',
      caught: 0,
      tally: '0 caught · 1 checked'
    })
  })

  it('inconclusive counts as checked and not caught; not comparable is no check at all', () => {
    const inconclusive = peerFacts(SWAP_PEER, askedPair(1, 'peer:swap', 'peer:other', 'inconclusive')).swapped
    expect(inconclusive).toMatchObject({ checked: 1, caught: 0, tally: '0 caught · 1 checked' })
    expect(inconclusive.text).not.toBe('Corroborated by referee')
    const notComparable = peerFacts(SWAP_PEER, askedPair(1, 'peer:swap', 'peer:other', 'not_comparable')).swapped
    expect(notComparable).toMatchObject({ text: 'Not tested', checked: 0, tally: 'not checked' })
  })

  it('never counts a verdict delivered by another node’s ask, or a mismatch inferred from the answers', () => {
    const delivered = [
      pairRow('a1', 'peer:swap', { bracket_id: 'b1', other_row: 'b1x', same_answer: false, verdict: 'contradicted:node:swap-node' }),
      pairRow('b1x', 'peer:other', { bracket_id: 'b1', other_row: 'a1', same_answer: false, verdict: 'contradicted:node:swap-node' })
    ]
    expect(peerFacts(SWAP_PEER, delivered).swapped).toMatchObject({ text: 'Not tested', checked: 0 })
    const notAdjudicated = [
      pairRow('a2', 'peer:swap', {
        bracket_id: 'b2',
        same_answer: false,
        referee_row: { state: 'not_adjudicated', reason: 'off' }
      })
    ]
    expect(peerFacts(SWAP_PEER, notAdjudicated).swapped.checked).toBe(0)
  })

  it('one pair is counted once even though both of its rows carry the verdict', () => {
    const rows = askedPair(1, 'peer:swap', 'peer:swap', 'contradicted:node:swap-node')
    expect(peerFacts(SWAP_PEER, rows).swapped.checked).toBe(1)
  })

  it('marks a peer that acted as referee on a pair this node asked', () => {
    const rows = askedPair(1, 'peer:a', 'peer:b', 'corroborated', 'node:swap-node')
    expect(peerFacts(SWAP_PEER, rows).actedAsReferee).toBe(true)
    expect(peerFacts(baseRow({ peer_id: 'peer:a' }), rows).actedAsReferee).toBe(false)
  })

  it('a peer a pair never named is Not tested', () => {
    const rows = askedPair(1, 'peer:a', 'peer:b', 'contradicted:node:a')
    expect(peerFacts(baseRow({ peer_id: 'peer:c' }), rows).swapped.text).toBe('Not tested')
  })
})

describe('peerFacts — review fixes', () => {
  it('a caught swap is never cleared when the row has no node id to match the verdict against', () => {
    const noIdentity = baseRow({ peer_id: 'peer:swap', identity: null, exchange_count: 1 })
    // The referee sealed the verdict naming this peer's node id, which this row does not carry.
    const rows = askedPair(1, 'peer:swap', 'peer:other', 'contradicted:node:swap-node')
    const { swapped } = peerFacts(noIdentity, rows)
    expect(swapped.text).not.toBe('Corroborated by referee')
    expect(swapped).toMatchObject({ text: 'Checked', tone: 'muted', caught: 0, checked: 1, tally: '0 caught · 1 checked' })
  })

  it('a peer is not marked as a referee by a verdict another node delivered', () => {
    const delivered = [
      pairRow('a1', 'peer:a', { bracket_id: 'b1', verdict: 'corroborated', referee_node_id: 'node:swap-node' })
    ]
    expect(peerFacts(SWAP_PEER, delivered).actedAsReferee).toBe(false)
  })

  it('Left something out always carries its denominator when records differ', () => {
    const row = baseRow({ exchange_count: 5, claims_refused: 2 })
    expect(peerFacts(row).leftOut.text).toBe('2 of 5 differ')
  })

  it('"Needs a look" follows what the row shows: a pane B verdict alone does not raise it', () => {
    const paneBOnly = baseRow({
      exchange_count: 3,
      verdicts: { state: 'contradicted', text: '', tally: { corroborated: 0, contradicted: 1, inconclusive: 0 } }
    })
    const view = dealtWithRowView(paneBOnly)
    expect(view.facts.swapped.text).toBe('Not tested')
    expect(view.needsALook).toBe(false)
  })

  it('"Needs a look" is raised by a caught swap, a differing record, a failed log check or a refusal', () => {
    const caught = askedPair(1, 'peer:swap', 'peer:other', 'contradicted:node:swap-node')
    expect(dealtWithRowView(SWAP_PEER, undefined, caught).needsALook).toBe(true)
    expect(dealtWithRowView(baseRow({ exchange_count: 2, claims_refused: 1 })).needsALook).toBe(true)
    expect(dealtWithRowView(baseRow({ history: { state: 'failed', text: null } })).needsALook).toBe(true)
    expect(dealtWithRowView(baseRow({ history: { state: 'refused', text: null } })).needsALook).toBe(true)
  })
})
