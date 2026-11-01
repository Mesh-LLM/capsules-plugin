import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { RECEIPT_PAGE_SENTENCE } from '@/features/capsules/components/SaveReceiptPage'
import { SecurityChecksView } from '@/features/capsules/components/SecurityChecksView'
import { sharedTheirsDetail } from '@/features/capsules/lib/security-checks-view'
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'
import type { ExchangeLedgerRow } from '@/features/capsules/lib/exchange-ledger'
import type { RecomputedIdentity } from '@/features/capsules/lib/recompute-identity'

function paneCRow(overrides: Partial<PaneCRow> = {}): PaneCRow {
  return {
    exchange_key: 'exch-cle',
    role_tag: 'ASKED',
    header_state: 'ok',
    properties: {
      task_binding: { state: 'PASS' },
      local_inclusion: { state: 'NOT_PRESENT' },
      checkpoint_signature: { state: 'NOT_PRESENT' },
      external_registration: { state: 'NOT_PRESENT' },
      continuity: { state: 'NOT_PRESENT' },
      identity_authority: { state: 'NOT_PRESENT' },
      capture_coverage: { state: 'PASS' },
      outcome_corroboration: { state: 'PASS' }
    },
    has_issue: false,
    mine: { state: 'present', capsule_id: 'mine-capsule-1' },
    theirs: { state: 'present', capsule_id: 'theirs-capsule-1' },
    unilateral: false,
    timestamp: '2026-09-08T16:58:05.412Z',
    ...overrides
  }
}

function ledgerRow(raw: PaneCRow): ExchangeLedgerRow {
  return {
    exchangeKey: raw.exchange_key,
    timestamp: raw.timestamp,
    roleTag: raw.role_tag,
    counterparty: 'node:aa11bb22',
    confirmed: true,
    localOnly: false,
    hasIssue: raw.has_issue,
    checksText: '—',
    rightCellState: { kind: 'closed', date: null },
    contentToggleState: { your: { kind: 'populated', date: null }, their: { kind: 'not_asked', date: null } },
    sessionId: null,
    twinBracketId: null,
    raw
  }
}

const RECOMPUTED_MATCH: RecomputedIdentity = { idMatch: true, signatureOk: true }

function renderView(overrides: Partial<PaneCRow> = {}, props: Partial<Parameters<typeof SecurityChecksView>[0]> = {}) {
  return render(
    <SecurityChecksView identity={RECOMPUTED_MATCH} localRecord={null} row={ledgerRow(paneCRow(overrides))} {...props} />
  )
}

/** Opens every group (they start closed) and returns the user. */
async function openAllGroups() {
  const user = userEvent.setup()
  for (const button of screen.getAllByRole('button', { expanded: false })) {
    if (button.closest('[data-check-group]')) await user.click(button)
  }
  return user
}

async function openRecord() {
  const user = userEvent.setup()
  await user.click(screen.getByRole('button', { name: /The record itself/ }))
  return user
}

describe('SecurityChecksView — inline, never a modal', () => {
  it('carries no dialog/alertdialog role anywhere in the subtree', () => {
    renderView()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument()
  })

  it('renders as an inline region, labelled with the exchange key', () => {
    renderView()
    expect(screen.getByRole('region', { name: /exch-cle/ })).toBeInTheDocument()
  })
})

describe('SecurityChecksView — four questions, each group closed until opened', () => {
  it('lists the four questions in order, each closed with a one-line summary over its total', () => {
    const { container } = renderView()
    const groups = Array.from(container.querySelectorAll('[data-check-group]'))
    expect(groups.map((g) => g.getAttribute('data-check-group'))).toEqual([
      'rewritten',
      'same_story',
      'advertised_model',
      'stands_behind'
    ])
    const questions = groups.map((g) => g.querySelector('button')?.textContent)
    expect(questions).toEqual([
      expect.stringContaining('Could anyone have rewritten this?'),
      expect.stringContaining('Do both sides tell the same story?'),
      expect.stringContaining('Was it the model they advertised?'),
      expect.stringContaining('Who stands behind it?')
    ])
    for (const group of groups) {
      expect(group.querySelector('button')).toHaveAttribute('aria-expanded', 'false')
      expect(group.querySelector('[data-check-line]')).toBeNull()
      expect(group.querySelector('[data-group-summary]')?.textContent).toMatch(/^\d+\/\d+ checked/)
    }
  })

  it('every count carries its denominator, in the headline and in each group summary', () => {
    const { container } = renderView()
    const headline = container.querySelector('[data-checks-headline]') as HTMLElement
    expect(headline.textContent).toMatch(/^\d+\/\d+ checked/)
    for (const piece of headline.textContent?.split(' · ') ?? []) expect(piece).toMatch(/\d+\/\d+/)
    expect(headline.textContent).not.toMatch(/%|score|grade/i)
  })

  it('a group opens and closes on its own, leaving the others alone', async () => {
    const user = userEvent.setup()
    renderView()
    const first = screen.getByRole('button', { name: /Could anyone have rewritten this/ })
    await user.click(first)
    expect(first).toHaveAttribute('aria-expanded', 'true')
    expect(document.querySelector('[data-check-group="rewritten"] [data-check-line]')).not.toBeNull()
    expect(document.querySelector('[data-check-group="same_story"] [data-check-line]')).toBeNull()
    await user.click(first)
    expect(first).toHaveAttribute('aria-expanded', 'false')
  })

  it('a group holding a failed check opens by itself: a failure is never behind a closed group', () => {
    renderView({ properties: { ...paneCRow().properties, checkpoint_signature: { state: 'FAIL' } } as never })
    expect(screen.getByRole('button', { name: /Could anyone have rewritten this/ })).toHaveAttribute(
      'aria-expanded',
      'true'
    )
    expect(screen.getByRole('button', { name: /Do both sides tell the same story/ })).toHaveAttribute(
      'aria-expanded',
      'false'
    )
  })

  it('a chip jump opens the group holding its line', () => {
    renderView({}, { highlightedPropertyKey: 'outcome_corroboration' })
    expect(screen.getByRole('button', { name: /Do both sides tell the same story/ })).toHaveAttribute(
      'aria-expanded',
      'true'
    )
    expect(document.querySelector('[data-check-line="Their signed record received"]')).not.toBeNull()
  })

  it('names the checks under the question each answers', async () => {
    renderView()
    await openAllGroups()
    const expected: Record<string, string[]> = {
      rewritten: [
        'Contents match the record’s id',
        'Signed with the node’s key',
        'Covered by a signed checkpoint',
        'Checkpoint builds on the one before',
        'Checkpoint held by an outside witness'
      ],
      same_story: [
        'Their signed record received',
        'Same request digest',
        'Same answer digest',
        'Record tied to the request'
      ],
      advertised_model: ['Same model identity', 'Referee verdict on this pair', 'Hardware attestation'],
      stands_behind: ['Signing key bound to an owner']
    }
    for (const [group, names] of Object.entries(expected)) {
      const section = document.querySelector(`[data-check-group="${group}"]`) as HTMLElement
      for (const name of names) expect(within(section).getByText(name), `${group}: ${name}`).toBeInTheDocument()
    }
  })

  it('has no "chain" in its words, and no score', async () => {
    const { container } = renderView()
    await openAllGroups()
    expect(container.textContent).not.toMatch(/\bchain\b/i)
  })
})

describe('SecurityChecksView — the headline: legend once, columns once', () => {
  it('says the legend once, in the design’s marks, even with every group open', async () => {
    renderView()
    await openAllGroups()
    expect(document.querySelectorAll('[data-check-source-legend]')).toHaveLength(1)
    expect(screen.getByText(/✓ checked here: your browser redid it just now/)).toBeInTheDocument()
    expect(screen.getByText(/◐ node says: taken from this node without re-checking/)).toBeInTheDocument()
  })

  it('names the two columns once', async () => {
    renderView()
    await openAllGroups()
    expect(screen.getAllByText('your record', { selector: 'p' })).toHaveLength(1)
    expect(screen.getAllByText('their record', { selector: 'p' })).toHaveLength(1)
  })

  it('names which record each side’s checks are about', () => {
    renderView({ theirs: { state: 'present', capsule_id: 'd'.repeat(64) } })
    const ids = document.querySelector('[data-record-ids]') as HTMLElement
    expect(ids).toHaveTextContent('mine-capsule-1')
    expect(ids).toHaveTextContent('d'.repeat(64))
  })
})

describe('SecurityChecksView — the record itself: one click further, readable or raw, with copy', () => {
  it('is closed by default; opening it shows identity, header and what it commits to, in that order', async () => {
    const { container } = renderView()
    expect(container.querySelector('[data-block-heading="identity"]')).toBeNull()
    await openRecord()
    const headings = Array.from(container.querySelectorAll('[data-block-heading]')).map((el) =>
      el.getAttribute('data-block-heading')
    )
    expect(headings).toEqual(['checks', 'identity', 'header', 'what it commits to'])
  })

  it('raw bytes are behind the [raw] switch inside the record, and copy sits beside it', async () => {
    renderView()
    const user = await openRecord()
    expect(screen.queryByText(/"mine"/)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /copy both/ })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'raw' }))
    expect(screen.getByText(/"mine"/)).toBeInTheDocument()
  })
})

/** The chip cell whose sentence is `detail` (p2 item 2: the sentence lives
 *  in the chip's tooltip, carried on the cell as `data-detail`). */
function cellWithDetail(detail: string): HTMLElement {
  const cells = Array.from(document.querySelectorAll<HTMLElement>('[data-detail]')).filter(
    (el) => el.getAttribute('data-detail') === detail
  )
  expect(cells.length, `no chip carries "${detail}"`).toBeGreaterThan(0)
  return cells[0]
}

/** The text a chip's tooltip carries (its aria-describedby copy). */
function chipTooltip(cell: HTMLElement): string {
  const id = cell.querySelector('[aria-describedby]')?.getAttribute('aria-describedby')
  return (id ? document.getElementById(id)?.textContent : '') ?? ''
}

describe('SecurityChecksView — p2 item 2: chip-only rows, each sentence moved word for word into its chip’s tooltip', () => {
  it('every sentence is in its chip’s tooltip, never printed beside the chip', async () => {
    renderView()
    await openAllGroups()
    for (const detail of [
      'checked in your browser',
      'No checkpoint covers this record — see Integrity.',
      'no checkpoint covers this record',
      'no receipt covers this record',
      'not linked to an owner'
    ]) {
      const cell = cellWithDetail(detail)
      expect(chipTooltip(cell)).toContain(detail)
      const visible = cell.cloneNode(true) as HTMLElement
      for (const hidden of visible.querySelectorAll('.sr-only')) hidden.remove()
      expect(visible.textContent).not.toContain(detail)
    }
  })

  it('a row reads name -> your chip -> their chip', async () => {
    renderView()
    await openAllGroups()
    const line = document.querySelector('[data-check-line="Contents match the record’s id"]') as HTMLElement
    const [name, yours, theirs] = Array.from(line.children) as HTMLElement[]
    expect(name.querySelector('[data-check-name]')?.textContent).toBe('Contents match the record’s id')
    expect(yours.querySelector('[data-detail]')).not.toBeNull()
    expect(theirs.querySelector('[data-detail]')).not.toBeNull()
  })

  it('the THEIRS sentence that repeats down the column is said once, as a column note, and left off those chips', async () => {
    renderView()
    await openAllGroups()
    const note = document.querySelector('[data-theirs-column-note]') as HTMLElement
    expect(note.textContent).toBe('not checked here')
    expect(screen.getAllByText('not checked here')).toHaveLength(1)
    const repeated = Array.from(document.querySelectorAll<HTMLElement>('[data-detail="not checked here"]'))
    expect(repeated.length).toBeGreaterThan(1)
    for (const cell of repeated) expect(chipTooltip(cell)).not.toContain('not checked here')
  })

  it('sharedTheirsDetail: only a sentence that actually repeats becomes the note', () => {
    const cell = (detail: string) => ({ state: 'NOT_CHECKED', label: 'not checked', detail, recomputed: false })
    const row = (key: string, detail: string | null) => ({
      key,
      label: key,
      group: 'g',
      yours: null,
      theirs: detail ? cell(detail) : null
    })
    expect(sharedTheirsDetail([row('a', 'x'), row('b', 'y')])).toBeNull()
    expect(sharedTheirsDetail([row('a', 'x'), row('b', 'x'), row('c', 'y'), row('d', null)])).toBe('x')
  })
})

describe('SecurityChecksView — L-M: recomputed-here vs from-sidecar are visually distinct', () => {
  it('content_binding/producer_signature carry a different class + data-source than a sidecar property', async () => {
    renderView()
    await openAllGroups()
    const recomputedCell = cellWithDetail('checked in your browser')
    const sidecarCell = cellWithDetail('No checkpoint covers this record — see Integrity.')
    expect(recomputedCell?.getAttribute('data-source')).toBe('recomputed-in-browser')
    expect(sidecarCell?.getAttribute('data-source')).toBe('from-sidecar')
    expect(recomputedCell?.className).not.toBe(sidecarCell?.className)
  })

  it('says the source in words (no coloured bar)', async () => {
    renderView()
    await openAllGroups()
    const recomputedCell = cellWithDetail('checked in your browser')
    expect(recomputedCell?.className).not.toMatch(/border-l-2/)
    expect(recomputedCell?.textContent).toContain('checked in your browser')
  })
})

describe('SecurityChecksView — capture_coverage: sentence or not present, never a bare pass chip', () => {
  it('renders the fixed sentence when present', async () => {
    renderView()
    await openAllGroups()
    expect(
      screen.getByText('captured by the plugin at this node’s serving boundary (rule: every served exchange)')
    ).toBeInTheDocument()
  })

  it('renders "not present" when the sidecar sends nothing for it', async () => {
    renderView({ properties: null })
    await openAllGroups()
    const line = document.querySelector('[data-check-line="Captured in full"]') as HTMLElement
    expect(line.textContent).toContain('not present')
    expect(line.querySelector('[data-check-mark]')).toHaveAttribute('data-check-mark', 'not_set_up')
  })
})

describe('SecurityChecksView — who stands behind it: one line, the owner key', () => {
  it('renders only "Signing key bound to an owner"; no always-not-set-up person line', async () => {
    renderView()
    await openAllGroups()
    expect(screen.getByText('Signing key bound to an owner')).toBeInTheDocument()
    expect(screen.queryByText('Owner bound to a person')).not.toBeInTheDocument()
    expect(document.querySelectorAll('[data-check-group="stands_behind"] [data-check-line]')).toHaveLength(1)
    expect(document.body.textContent).not.toContain('Owner: …')
  })
})

describe('SecurityChecksView — every chip opens a four-part explanation', () => {
  it('clicking a chip reveals what it means / what this view found / what it does not establish / how to change it', async () => {
    renderView()
    const user = await openAllGroups()
    await user.click(screen.getAllByText('established')[0])
    expect(screen.getByText(/^What this means:/)).toBeInTheDocument()
    expect(screen.getByText(/^What this view found:/)).toBeInTheDocument()
    expect(screen.getByText(/^What it does not establish:/)).toBeInTheDocument()
    expect(screen.getByText(/^How to change it:/)).toBeInTheDocument()
  })
})

describe('SecurityChecksView — rendered property set', () => {
  it('renders all ten manifesto properties, including task_binding, across the groups', async () => {
    renderView()
    await openAllGroups()
    for (const key of [
      'content_binding',
      'producer_signature',
      'task_binding',
      'local_inclusion',
      'checkpoint_signature',
      'external_registration',
      'continuity',
      'identity_authority',
      'capture_coverage',
      'outcome_corroboration'
    ]) {
      expect(document.querySelector(`[data-check-line][id$="${key}"]`), key).not.toBeNull()
    }
  })
})

describe('SecurityChecksView — digests: short in the group, whole on hover', () => {
  const localRecord = {
    effect: { request_digest: 'a'.repeat(64), response_digest: 'b'.repeat(64) },
    model_attestation: { model_id: 'model-x' }
  } as never

  it('shows a short digest with the whole one on hover, never the whole one as text', async () => {
    renderView({}, { localRecord })
    await openAllGroups()
    const digest = document.querySelector(`[data-digest="${'a'.repeat(64)}"]`) as HTMLElement
    expect(digest).toHaveAttribute('title', 'a'.repeat(64))
    expect(digest.textContent).toBe('aaaaaaaa…aaaa')
  })
})

describe('SecurityChecksView — same request/answer/model: same only after a REAL fetch, never mirrored', () => {
  const localRecord = {
    effect: { request_digest: 'a'.repeat(64), response_digest: 'b'.repeat(64) },
    model_attestation: { model_id: 'model-x' }
  } as never
  const found = (response: string) => ({
    status: 'found' as const,
    idMatch: true,
    signatureOk: true,
    peerRecord: {
      effect: { request_digest: 'a'.repeat(64), response_digest: response },
      model_attestation: { model_id: 'model-x' }
    },
    fetch: () => {}
  })
  const peerRow = { theirs: { state: 'NOT_CHECKED', capsule_id: 'a'.repeat(64), peer_id: 'peer-1' } }

  it('MUTANT-GUARD: a CLOSED row with no fetched record never reads "same"', async () => {
    renderView({}, { localRecord })
    await openAllGroups()
    for (const name of ['Same request digest', 'Same answer digest', 'Same model identity']) {
      const line = document.querySelector(`[data-check-line="${name}"]`) as HTMLElement
      expect(within(line).queryByText('same')).not.toBeInTheDocument()
    }
  })

  it('once a real fetch holds the peer’s own matching record, "same" reads for the three fields with a peer-record equivalent', async () => {
    renderView(peerRow, { localRecord, theirsRecompute: found('b'.repeat(64)) })
    await openAllGroups()
    for (const name of ['Same request digest', 'Same answer digest', 'Same model identity']) {
      const line = document.querySelector(`[data-check-line="${name}"]`) as HTMLElement
      expect(within(line).getByText('same'), name).toBeInTheDocument()
    }
  })

  it('a record that differs reads "differs", and its group is open without a click', () => {
    renderView(peerRow, { localRecord, theirsRecompute: found('c'.repeat(64)) })
    expect(screen.getByRole('button', { name: /Do both sides tell the same story/ })).toHaveAttribute(
      'aria-expanded',
      'true'
    )
    const line = document.querySelector('[data-check-line="Same answer digest"]') as HTMLElement
    expect(within(line).getByText('differs')).toBeInTheDocument()
    expect(document.querySelector(`[data-digest="${'c'.repeat(64)}"]`)).not.toBeNull()
  })

  it('an OPEN row (theirs absent) renders nothing to compare: no "same", no "differs"', async () => {
    renderView({ theirs: { state: 'absent', capsule_id: null } }, { localRecord })
    await openAllGroups()
    expect(screen.queryByText('same')).not.toBeInTheDocument()
    expect(screen.queryByText('differs')).not.toBeInTheDocument()
  })
})

describe('SecurityChecksView — referee verdict follows the asked-and-sealed rule', () => {
  const twin = (referee_row: unknown) =>
    ({ bracket_id: 'b1', same_answer: false, other_row: null, referee_row }) as never

  it('shows a ruling this node asked for and holds', async () => {
    renderView({ twin: twin({ state: 'adjudicated', verdict: 'contradicted:peer-9', referee: 'ref-1', tier: 1 }) })
    await openAllGroups()
    const line = document.querySelector('[data-check-line="Referee verdict on this pair"]') as HTMLElement
    expect(within(line).getByText('contradicted · not matched to a machine')).toBeInTheDocument()
    expect(within(line).queryByText('agreed')).not.toBeInTheDocument()
  })

  it('on a caught swap, only the row naming the contradicted party reads wrong answer and opens as failed', async () => {
    const naming = twin({ state: 'adjudicated', verdict: 'contradicted:peer-9', referee: 'ref-1', tier: 1 })
    renderView({ twin: naming, counterparty: 'peer-9' })
    expect(screen.getByRole('button', { name: /Was it the model they advertised/ })).toHaveAttribute(
      'aria-expanded',
      'true'
    )
    const line = document.querySelector('[data-check-line="Referee verdict on this pair"]') as HTMLElement
    expect(within(line).getByText('wrong answer')).toBeInTheDocument()
    expect(within(line).queryByText('agreed')).not.toBeInTheDocument()
  })

  it('the row that does not name the party is not failed, and its group stays closed', () => {
    renderView({
      twin: twin({ state: 'adjudicated', verdict: 'contradicted:peer-9', referee: 'ref-1', tier: 1 }),
      counterparty: 'peer-2'
    })
    expect(screen.getByRole('button', { name: /Was it the model they advertised/ })).toHaveAttribute(
      'aria-expanded',
      'false'
    )
  })

  it('a pair with no ruling reads "not checked", never an inferred mismatch', async () => {
    renderView({ twin: twin({ state: 'not_adjudicated', reason: 'off' }) })
    await openAllGroups()
    const line = document.querySelector('[data-check-line="Referee verdict on this pair"]') as HTMLElement
    expect(within(line).getByText('not checked')).toBeInTheDocument()
  })

  it('a missing model id on our side is never a difference: theirs reads not checked, nothing fails', async () => {
    const theirsRecompute = {
      status: 'found' as const,
      idMatch: true,
      signatureOk: true,
      peerRecord: { model_attestation: { model_id: 'model-x' } },
      fetch: () => {}
    }
    renderView(
      { theirs: { state: 'NOT_CHECKED', capsule_id: 'a'.repeat(64), peer_id: 'peer-1' } },
      { localRecord: {} as never, theirsRecompute }
    )
    await openAllGroups()
    const line = document.querySelector('[data-check-line="Same model identity"]') as HTMLElement
    expect(within(line).queryByText(/differs/)).not.toBeInTheDocument()
    expect(within(line).getByText('not checked')).toBeInTheDocument()
  })

  it('a failed coverage cell is a failure, not a check: it opens its group', () => {
    renderView({ properties: { ...paneCRow().properties, capture_coverage: { state: 'FAIL' } } as never })
    expect(screen.getByRole('button', { name: /Could anyone have rewritten this/ })).toHaveAttribute(
      'aria-expanded',
      'true'
    )
  })

  it('a row that is not one of a pair says so', async () => {
    renderView()
    await openAllGroups()
    const line = document.querySelector('[data-check-line="Referee verdict on this pair"]') as HTMLElement
    expect(within(line).getByText('not a pair')).toBeInTheDocument()
  })
})

describe('SecurityChecksView — per-row "Save receipt page"', () => {
  it('offers the receipt page, with its sentence, in place of the JSON evidence file', () => {
    renderView()
    expect(screen.getByRole('button', { name: 'Save receipt page' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Save evidence file' })).not.toBeInTheDocument()
    expect(screen.getByText(RECEIPT_PAGE_SENTENCE)).toBeInTheDocument()
  })

  it('p2 item 1: no inert "open in Logs" -- it cannot link yet, so it is not shown', () => {
    renderView()
    expect(screen.queryByRole('button', { name: /open in Logs/i })).not.toBeInTheDocument()
    for (const button of screen.getAllByRole('button')) expect(button).not.toBeDisabled()
  })
})
