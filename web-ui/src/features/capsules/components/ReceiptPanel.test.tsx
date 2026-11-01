// The receipt on a row, each case rendered from a real bundle: the
// agent-action-capsule strict vector `incomplete-producer-selected` (a
// producer-selected bundle, the shape the plugin's receipt routes serve) and
// the composed/v1 vector `agree-with-checkpoints` (two copies that agree). The
// bytes are the vectors' own, copied unchanged.
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { ReceiptPanel } from '@/features/capsules/components/ReceiptPanel'
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'
import { receiptPath } from '@/features/capsules/api/receiptClient'
import { checkReceiptBundle, receiptCase, receiptRequest, receiptView } from '@/features/capsules/lib/receipt-view'
import composedAgree from '@/features/capsules/lib/receipt-fixtures/composed-agree.bundle.json'
import producerSelected from '@/features/capsules/lib/receipt-fixtures/producer-selected.bundle.json'

const EXCHANGE_RECORD = 'ab'.repeat(32)

const payerRow = {
  role_tag: 'ASKED',
  mine: { state: 'ok', capsule_id: EXCHANGE_RECORD },
  settlement: { observed_by: 'payer', state: 'settled', terms_digests: [], entries: [] }
} as unknown as PaneCRow

const providerRow = {
  role_tag: 'SERVED',
  mine: { state: 'ok', capsule_id: null },
  provider_settlement: {
    observed_by: 'provider',
    state: 'settled',
    terms_digests: [],
    entries: [],
    exchange_ids: ['ex-1']
  }
} as unknown as PaneCRow

/** Answer the receipt route with `body`, and remember the path asked. */
function routeAnswers(body: unknown, ok = true, status = 200) {
  const fetchSpy = vi.fn().mockResolvedValue({ ok, status, json: async () => body } as Response)
  vi.stubGlobal('fetch', fetchSpy)
  return fetchSpy
}

/** The same SubtleCrypto with Ed25519 import refused, as a browser without it
 *  does (the runtime probes `importKey` for `NotSupportedError`). */
function withoutEd25519() {
  const real = globalThis.crypto.subtle
  const subtle = {
    digest: real.digest.bind(real),
    importKey: async () => {
      throw Object.assign(new Error('Ed25519 is not supported'), { name: 'NotSupportedError' })
    }
  }
  vi.stubGlobal('crypto', { subtle, getRandomValues: globalThis.crypto.getRandomValues.bind(globalThis.crypto) })
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

async function check() {
  await userEvent.click(screen.getByRole('button', { name: 'Check receipt' }))
}

describe('ReceiptPanel', () => {
  it('shows "your receipt only" for the payer receipt, with every count over its denominator', async () => {
    const fetchSpy = routeAnswers({ state: 'bundle', bundle: JSON.stringify(producerSelected) })
    render(<ReceiptPanel row={payerRow} />)
    await check()
    const label = await screen.findByText('Receipt: your receipt only')
    expect(label).toHaveAttribute('data-receipt-case', 'your receipt only')
    // 2 records in the vector, both bound to the signed checkpoint.
    expect(screen.getByText(/2 of 2 records in the receipt are tied to a signed checkpoint/)).toBeInTheDocument()
    expect(String(fetchSpy.mock.calls[0][0])).toContain(
      `/api/plugins/capsules/http/deal-receipt-bundle?capsule_id=${EXCHANGE_RECORD}`
    )
  })

  it('shows "your receipt only" for the provider receipt, asked by the host exchange id', async () => {
    const fetchSpy = routeAnswers({ state: 'bundle', bundle: JSON.stringify(producerSelected) })
    render(<ReceiptPanel row={providerRow} />)
    await check()
    await screen.findByText('Receipt: your receipt only')
    expect(String(fetchSpy.mock.calls[0][0])).toContain('http/provider-receipt-bundle?exchange_id=ex-1')
  })

  it('shows "stamped by both" for two verified copies that agree', async () => {
    routeAnswers({ state: 'bundle', bundle: JSON.stringify(composedAgree) })
    render(<ReceiptPanel row={payerRow} />)
    await check()
    expect(await screen.findByText('Receipt: stamped by both')).toBeInTheDocument()
  })

  it('shows "no record" for a refusal from the route, not an error', async () => {
    routeAnswers({ state: 'refused', why: 'this node holds no deal for that exchange' })
    render(<ReceiptPanel row={payerRow} />)
    await check()
    expect(await screen.findByText('Receipt: no record')).toBeInTheDocument()
    expect(screen.queryByText(/could not be loaded/)).not.toBeInTheDocument()
  })

  it('says it cannot check the receipt in a browser without Ed25519, with no verdict', async () => {
    routeAnswers({ state: 'bundle', bundle: JSON.stringify(producerSelected) })
    withoutEd25519()
    render(<ReceiptPanel row={payerRow} />)
    await check()
    await waitFor(() => expect(screen.getByText(/this browser can't check the receipt/)).toBeInTheDocument())
    expect(screen.getByText(/offline viewer/)).toBeInTheDocument()
    expect(screen.queryByText(/Receipt:/)).not.toBeInTheDocument()
    expect(screen.queryByText(/did not verify/)).not.toBeInTheDocument()
  })

  it('does not call a tampered bundle a receipt', async () => {
    const tampered = JSON.parse(JSON.stringify(producerSelected))
    tampered.records[0].capsule_id = 'f'.repeat(64)
    routeAnswers({ state: 'bundle', bundle: JSON.stringify(tampered) })
    render(<ReceiptPanel row={payerRow} />)
    await check()
    expect(await screen.findByText(/the receipt did not verify: do not rely on it/)).toBeInTheDocument()
    expect(screen.queryByText(/Receipt:/)).not.toBeInTheDocument()
  })

  it('shows a route failure as a load error, never as a case', async () => {
    routeAnswers({}, false, 500)
    render(<ReceiptPanel row={payerRow} />)
    await check()
    expect(await screen.findByText(/could not be loaded here/)).toBeInTheDocument()
    expect(screen.queryByText(/Receipt:/)).not.toBeInTheDocument()
  })

  it('draws nothing for rows that are not a paid exchange this node can name', () => {
    const rows = [
      { role_tag: 'ASKED', mine: { capsule_id: EXCHANGE_RECORD }, settlement: null },
      { role_tag: 'ASKED', mine: { capsule_id: EXCHANGE_RECORD }, settlement: { state: 'terms_only' } },
      { role_tag: 'ASKED', mine: { capsule_id: null }, settlement: { state: 'settled' } },
      { role_tag: 'SERVED', mine: {}, provider_settlement: { state: 'settled', exchange_ids: ['a', 'b'] } }
    ] as unknown as PaneCRow[]
    for (const row of rows) {
      const { container } = render(<ReceiptPanel row={row} />)
      expect(container).toBeEmptyDOMElement()
      cleanup()
    }
  })
})

describe('ReceiptPanel states', () => {
  it('shows a refusal that is not "no record" as "no receipt yet:" with the route\'s reason word for word', async () => {
    routeAnswers({ state: 'refused', why: 'no signed checkpoint covers the deal yet' })
    render(<ReceiptPanel row={payerRow} />)
    await check()
    expect(await screen.findByText('no receipt yet: no signed checkpoint covers the deal yet')).toBeInTheDocument()
    expect(screen.queryByText(/Receipt: no record/)).not.toBeInTheDocument()
    expect(screen.queryByText(/holds no sealed deal/)).not.toBeInTheDocument()
  })

  it('shows the provider route\'s own refusal, with no payer-only sentence', async () => {
    const why = 'this node holds no single served record for that exchange'
    routeAnswers({ state: 'refused', why })
    render(<ReceiptPanel row={providerRow} />)
    await check()
    expect(await screen.findByText(why)).toBeInTheDocument()
    expect(screen.queryByText(/sealed deal/)).not.toBeInTheDocument()
  })

  it.each([
    ['this node noted no payment received for that exchange', false],
    ['this node holds no single served record for that exchange', true],
    ['this node holds no deal for that exchange', true],
    ['the deal has no report yet', false],
    ['the payload of deal record abc is not kept', false]
  ])('maps the refusal "%s" (no record: %s)', async (why, noRecord) => {
    const view = await receiptView({ kind: 'refused', why })
    expect(view.kind).toBe(noRecord ? 'no_record' : 'no_receipt_yet')
  })

  it('lets the owner ask again after a load error', async () => {
    routeAnswers({}, false, 500)
    render(<ReceiptPanel row={payerRow} />)
    await check()
    await screen.findByText(/could not be loaded here/)
    routeAnswers({ state: 'bundle', bundle: JSON.stringify(producerSelected) })
    await userEvent.click(screen.getByRole('button', { name: 'Check again' }))
    expect(await screen.findByText('Receipt: your receipt only')).toBeInTheDocument()
  })

  it('announces its result in a live status region and keeps the button mounted', async () => {
    routeAnswers({ state: 'refused', why: 'the deal has no report yet' })
    render(<ReceiptPanel row={payerRow} />)
    const button = screen.getByRole('button', { name: 'Check receipt' })
    await userEvent.click(button)
    const status = screen.getByRole('status')
    await waitFor(() => expect(status).toHaveTextContent('no receipt yet: the deal has no report yet'))
    expect(button).toBeInTheDocument()
  })

  it('shows a bundle served as an object, not as its text, as a load error', async () => {
    routeAnswers({ state: 'bundle', bundle: producerSelected })
    render(<ReceiptPanel row={payerRow} />)
    await check()
    expect(await screen.findByText(/could not be loaded here/)).toBeInTheDocument()
    expect(screen.queryByText(/Receipt:/)).not.toBeInTheDocument()
  })

  it('reads text that is not JSON as did-not-verify, not a load error', async () => {
    routeAnswers({ state: 'bundle', bundle: '{not json' })
    render(<ReceiptPanel row={payerRow} />)
    await check()
    expect(await screen.findByText(/the receipt did not verify: do not rely on it/)).toBeInTheDocument()
  })

  it('reads a bundle the runtime cannot read as did-not-verify, not a load error', async () => {
    routeAnswers({ state: 'bundle', bundle: JSON.stringify({ not: 'a bundle' }) })
    render(<ReceiptPanel row={payerRow} />)
    await check()
    expect(await screen.findByText(/the receipt did not verify: do not rely on it/)).toBeInTheDocument()
    expect(screen.queryByText(/could not be loaded/)).not.toBeInTheDocument()
  })

  it('offers "Save bundle" in the can\'t-check and did-not-verify states, saving the bundle served', async () => {
    const created: Blob[] = []
    const urlStub = {
      createObjectURL: (blob: Blob) => (created.push(blob), 'blob:x'),
      revokeObjectURL: () => {}
    }
    vi.stubGlobal(
      'URL',
      Object.assign(function () {}, urlStub)
    )
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})

    routeAnswers({ state: 'bundle', bundle: JSON.stringify(producerSelected) })
    withoutEd25519()
    render(<ReceiptPanel row={payerRow} />)
    await check()
    await userEvent.click(await screen.findByRole('button', { name: 'Save bundle' }))
    // The bytes the node served, unchanged.
    expect(await created[0].text()).toBe(JSON.stringify(producerSelected))
    cleanup()
    vi.unstubAllGlobals()
    vi.stubGlobal(
      'URL',
      Object.assign(function () {}, urlStub)
    )

    const tampered = { ...producerSelected, records: [{ ...producerSelected.records[0], capsule_id: 'f'.repeat(64) }] }
    routeAnswers({ state: 'bundle', bundle: JSON.stringify(tampered) })
    render(<ReceiptPanel row={payerRow} />)
    await check()
    await userEvent.click(await screen.findByRole('button', { name: 'Save bundle' }))
    expect(await created[1].text()).toBe(JSON.stringify(tampered))
  })

  it('does not offer "Save bundle" for a receipt that checked', async () => {
    routeAnswers({ state: 'bundle', bundle: JSON.stringify(producerSelected) })
    render(<ReceiptPanel row={payerRow} />)
    await check()
    await screen.findByText('Receipt: your receipt only')
    expect(screen.queryByRole('button', { name: 'Save bundle' })).not.toBeInTheDocument()
  })

  it('says it cannot check where SHA-256 is unavailable (an insecure origin), with no verdict', async () => {
    vi.stubGlobal('crypto', undefined)
    expect((await checkReceiptBundle(JSON.stringify(producerSelected))).kind).toBe('cannot_check')
  })

  it('reads anything the runtime throws on as did-not-verify', async () => {
    expect((await checkReceiptBundle('null')).kind).toBe('did_not_verify')
  })
})

describe('receiptCase', () => {
  /** A context shaped as the runtime reports a composed/v1 block; only the
   *  fields the case reads are set (a signed fixture cannot be altered
   *  without breaking its signatures). */
  const claim = (status: 'pass' | 'fail') => ({ status, findings: [] })
  const memberClaims = (status: 'pass' | 'fail') => ({
    graphClosure: claim(status),
    intervalCoverage: claim('pass'),
    perRecordMembership: claim('pass')
  })
  const agreeing = (over: Record<string, unknown> = {}) => ({
    malformed: false,
    status: 'pass',
    members: [
      { outcome: 'artifact', bundle: memberClaims('pass') },
      { outcome: 'artifact', bundle: memberClaims('pass') }
    ],
    joins: [{ derived: 'agree', result: 'derived_matches' }],
    corroboration: [{ result: 'corroborating' }],
    ...over
  })
  const contextOf = (composed: unknown) => ({ extensions: [{ composed }] }) as never

  it('is "both" only for two agreeing, corroborating, passing copies', () => {
    expect(receiptCase(contextOf(agreeing()))).toBe('both')
  })

  it.each([
    ['a join that disagrees', { joins: [{ derived: 'mismatch', result: 'derived_matches' }] }],
    ['a redundant pair', { corroboration: [{ result: 'redundant' }] }],
    ['a single artifact', { members: [{ outcome: 'artifact', bundle: memberClaims('pass') }] }],
    ['no corroboration', { corroboration: [] }],
    ['a block that did not pass', { status: 'fail' }],
    [
      'a copy whose own claims failed',
      { members: [{ outcome: 'artifact', bundle: memberClaims('fail') }, { outcome: 'artifact' }] }
    ]
  ])('is not "both" for %s', (_name, over) => {
    expect(receiptCase(contextOf(agreeing(over)))).toBe('one_sided')
  })

  it('is not "both" with no composed block', () => {
    expect(receiptCase({ extensions: [] } as never)).toBe('one_sided')
  })
})

describe('receiptRequest', () => {
  it('names the payer route by the exchange record and the provider route by the host exchange id', () => {
    expect(receiptRequest(payerRow)).toEqual({ side: 'payer', capsuleId: EXCHANGE_RECORD })
    expect(receiptRequest(providerRow)).toEqual({ side: 'provider', exchangeId: 'ex-1' })
    expect(receiptPath({ side: 'provider', exchangeId: 'a b' })).toBe('http/provider-receipt-bundle?exchange_id=a%20b')
  })
})
