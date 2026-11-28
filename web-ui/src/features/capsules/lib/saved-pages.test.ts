import { webcrypto } from 'node:crypto'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  NO_PAID_DEAL_WHY,
  historyPage,
  receiptPage,
  sealedSettlementPage
} from '@/features/capsules/lib/saved-pages'
import composedAgree from '@/features/capsules/lib/receipt-fixtures/composed-agree.bundle.json'
import producerSelected from '@/features/capsules/lib/receipt-fixtures/producer-selected.bundle.json'
// A payer's deal receipt as the plugin's own route cuts it (see ReceiptPanel.test.tsx).
import meshPayerDeal from '@/features/capsules/lib/receipt-fixtures/mesh-payer-deal.bundle.json'
// A provider's own receipt as the plugin's own route cuts it (see ReceiptPanel.test.tsx).
import meshProviderSelected from '@/features/capsules/lib/receipt-fixtures/mesh-provider-selected.bundle.json'
import { NOT_DRAWN_LINES } from '@/features/capsules/lib/receipt-view'
import { embeddedBundle as embedded, openSavedPage as open, savedBytes } from '@/lib/test/open-saved-page'

const fixture = JSON.parse(
  readFileSync(path.resolve(process.cwd(), '../crates/evidence-plugin/tests/fixtures/evidence_answers_5d2d102.json'), 'utf8')
) as Record<string, Record<string, unknown>>
// The bytes a node served: the reply as the node wrote it.
const served = `${JSON.stringify(fixture.history_card)}\n`
const SAVED = '2026-10-29T18:00:00Z'
const NODE = {
  nodeKeyId: 'a'.repeat(64),
  sharing: {
    standard_history: true,
    history_segments: 'counterparties',
    record_at_completion: 'counterparty',
    adjudications: 'deliver_to_subjects',
    exchange_corroboration: false
  } as const
}

describe('the History page, opened offline', () => {
  it('verifies the embedded answer itself, draws it through the shared view, and hands back the JSON byte for byte', async () => {
    const { html } = historyPage(served, SAVED, NODE)
    expect(Buffer.from(embedded(html)).equals(Buffer.from(served, 'utf8'))).toBe(true)

    const { dom, requested, text } = await open(html)
    expect(dom.window.document.querySelector('.cv-history')).not.toBeNull()
    expect(text).toContain('every checkpoint signature checks')
    expect(text).toContain('Checked: Every checkpoint is signed by the key that answered')
    // This page checks no witness receipt, no reply signature, no node key.
    expect(text).toContain('Not checked here: A witness time-stamped these records')
    expect(text).toContain("Not checked here: The signing key is the node's published key")
    expect(text).not.toContain('Failed')
    expect(requested).toEqual([])

    expect((await savedBytes(dom)).equals(Buffer.from(served, 'utf8'))).toBe(true)
  })

  it('checks the witness receipts only under witnesses the reader pastes', async () => {
    const witnessed = readFileSync(
      path.resolve(process.cwd(), '../crates/evidence-plugin/tests/fixtures/history_card_2_witnessed.json'),
      'utf8'
    )
    const { dom, requested, text } = await open(historyPage(witnessed, SAVED, NODE).html)
    // No list: the receipts are not checked, and the page says so in the list, the chip and every badge.
    expect(text).toContain('Not checked here: A witness time-stamped these records')
    expect(text).toContain('Time stamps not checked here')
    expect(text).toContain('A checkpoint taken shortly before this page was saved may show as not checked yet')
    const doc = dom.window.document
    const list = (key: string) => JSON.stringify({ witnesses: [{ name: 'my witness', keys: [key] }] })
    const apply = async (value: string) => {
      ;(doc.getElementById('witness-list') as HTMLTextAreaElement).value = value
      ;(doc.getElementById('witness-apply') as HTMLButtonElement).click()
      await new Promise((r) => setTimeout(r, 300))
    }
    await apply('not a list')
    expect(doc.getElementById('witness-note')!.textContent).toContain('not a witness list')
    const key = '302a300506032b6570032100d54207da194977dcf46adbfec2bc2e75b52d5a8a42184fedfdc00024f0e3e8da'
    await apply(list(key))
    expect(doc.getElementById('witness-note')!.textContent).toContain('1 witness you named')
    expect(doc.querySelector('main')!.textContent).not.toContain('Not checked here: A witness time-stamped these records')
    expect(doc.querySelector('main')!.textContent).toContain('Checked: A witness time-stamped these records')
    // The chip and every checkpoint's badge follow the same verdict as the list.
    const main = doc.querySelector('main')!.textContent!
    expect(main).toContain('Time-stamped: all 19')
    expect(main).not.toContain('Time stamps not checked here')
    const stamps = Array.from(doc.querySelectorAll('.cvh-stamp')).filter((e) => e.textContent!.startsWith('TIME-STAMPED'))
    expect(stamps).toHaveLength(19)
    for (const stamp of stamps) {
      expect(stamp.getAttribute('data-state')).toBe('passed')
      expect(stamp.textContent).toContain('my witness')
    }
    // A key that does not verify the receipt fails it, and nothing was fetched.
    await apply(list('302a300506032b6570032100' + '11'.repeat(32)))
    expect(doc.querySelector('main')!.textContent).toContain("Didn't verify: A witness time-stamped these records")
    // The list, the chip and the badges all say it didn't verify, and the checkpoints are still drawn.
    expect(doc.querySelector('main')!.textContent).toContain("Time stamps didn't verify")
    expect(doc.querySelector('main')!.textContent).not.toContain('No checkpoints yet')
    // The other checks still read as they did: the lock was checked, whatever the witness said.
    expect(doc.querySelector('main')!.textContent).toContain('Locked as it happened.')
    expect(doc.querySelector('main')!.textContent).not.toContain('did not check how these records were locked')
    expect(doc.querySelectorAll('.cvh-stamp[data-state="failed"]').length).toBeGreaterThan(0)
    expect(requested).toEqual([])
  })

  it('names the checkpoint the witness has not registered, in the list and not only in the chip', async () => {
    const reply = JSON.parse(
      readFileSync(path.resolve(process.cwd(), '../crates/evidence-plugin/tests/fixtures/history_card_2_witnessed.json'), 'utf8')
    ) as { anchor: { digest: string }; witness_receipts: { checkpoint: string }[] }
    // A page saved right after a checkpoint: the answer holds no receipt yet for the last (anchor) checkpoint.
    const before = reply.witness_receipts.length
    reply.witness_receipts = reply.witness_receipts.filter((r) => r.checkpoint !== reply.anchor.digest)
    expect(reply.witness_receipts).toHaveLength(before - 1)
    const { dom } = await open(historyPage(`${JSON.stringify(reply)}\n`, SAVED, NODE).html)
    const doc = dom.window.document
    const key = '302a300506032b6570032100d54207da194977dcf46adbfec2bc2e75b52d5a8a42184fedfdc00024f0e3e8da'
    ;(doc.getElementById('witness-list') as HTMLTextAreaElement).value = JSON.stringify({ witnesses: [{ name: 'my witness', keys: [key] }] })
    ;(doc.getElementById('witness-apply') as HTMLButtonElement).click()
    await new Promise((r) => setTimeout(r, 300))
    const main = doc.querySelector('main')!.textContent!
    expect(main).toContain('Time-stamped: 18 of 19')
    // The one checkpoint the chip is missing is the one the list names, with that row's own cut time.
    const stamps = Array.from(doc.querySelectorAll('.cvh-stamp')).filter((e) => e.textContent!.startsWith('TIME-STAMPED'))
    expect(stamps).toHaveLength(19)
    const unstamped = stamps.flatMap((e, i) => (e.getAttribute('data-state') === 'passed' ? [] : [i + 1]))
    expect(unstamped).toEqual([19])
    const rows = Array.from(doc.querySelectorAll('.cvh-row'))
    expect(rows).toHaveLength(19)
    const cut = rows[18]!.querySelector('.cvh-row-title')!.textContent!.replace(/^Cut /, '')
    expect(main).toContain(
      `Not checked here: A witness time-stamped these records. Checkpoint 19 (cut ${cut}) is not registered with the witness yet.`
    )
  })

  it('names a middle checkpoint the witness has not registered, and does not say Checked (#359)', async () => {
    const reply = JSON.parse(
      readFileSync(path.resolve(process.cwd(), '../crates/evidence-plugin/tests/fixtures/history_card_2_witnessed.json'), 'utf8')
    ) as { witness_receipts: { checkpoint: string; witness: Record<string, unknown> }[] }
    // The 10th receipt is for a middle checkpoint (the fixture holds 19, one per checkpoint, in checkpoint order).
    // Pick the dropped checkpoint by digest, as one that is neither the anchor (the last) nor the first.
    const anchor = (reply as unknown as { anchor: { digest: string } }).anchor.digest
    const dropped = reply.witness_receipts.filter((r) => r.checkpoint !== anchor)[9]!.checkpoint
    reply.witness_receipts = reply.witness_receipts.filter((r) => r.checkpoint !== dropped)
    const { dom } = await open(historyPage(`${JSON.stringify(reply)}\n`, SAVED, NODE).html)
    const doc = dom.window.document
    const key = '302a300506032b6570032100d54207da194977dcf46adbfec2bc2e75b52d5a8a42184fedfdc00024f0e3e8da'
    ;(doc.getElementById('witness-list') as HTMLTextAreaElement).value = JSON.stringify({ witnesses: [{ name: 'my witness', keys: [key] }] })
    ;(doc.getElementById('witness-apply') as HTMLButtonElement).click()
    await new Promise((r) => setTimeout(r, 300))
    const main = doc.querySelector('main')!.textContent!
    expect(main).toContain('Time-stamped: 18 of 19')
    expect(main).not.toContain('Checked: A witness time-stamped these records')
    const stamps = Array.from(doc.querySelectorAll('.cvh-stamp')).filter((e) => e.textContent!.startsWith('TIME-STAMPED'))
    const unstamped = stamps.flatMap((e, i) => (e.getAttribute('data-state') === 'passed' ? [] : [i + 1]))
    expect(unstamped).toHaveLength(1)
    const rows = Array.from(doc.querySelectorAll('.cvh-row'))
    const n = unstamped[0]!
    // A middle one: not the first and not the last, so this is not #358's last-open case again.
    expect(n).toBeGreaterThan(1)
    expect(n).toBeLessThan(stamps.length)
    expect(stamps[stamps.length - 1]!.getAttribute('data-state')).toBe('passed')
    const cut = rows[n - 1]!.querySelector('.cvh-row-title')!.textContent!.replace(/^Cut /, '')
    expect(main).toContain(
      `Not checked here: A witness time-stamped these records. Checkpoint ${n} (cut ${cut}) is not registered with the witness yet.`
    )
  })

  it('shows what this node shares, from the settings the node reported', async () => {
    const { text } = await open(historyPage(served, SAVED, NODE).html)
    expect(text).toContain('What this node shares')
    expect(text).toContain('With anyone: the Service History.')
    // The viewer 0.24 says what the node's settings leave unstated (these settings omit the witnesses and the referee setting).
    expect(text).toContain("This node's settings don't say")
    expect(text).toContain("Only with the other side of an exchange, when they ask: that exchange's record.")
    const off = { ...NODE, sharing: { ...NODE.sharing, standard_history: false, history_segments: 'off' as const } }
    const { text: offText } = await open(historyPage(served, SAVED, off).html)
    expect(offText).toContain('The Service History: only the other side of an exchange gets it (off for anyone else on this node).')
    expect(offText).toContain("The other side of an exchange can't ask for its record (off on this node).")
  })

  it('refers to nothing outside itself', () => {
    const { html } = historyPage(served, SAVED, NODE)
    expect(html).not.toMatch(/(?:src|href)\s*=\s*["']?(?:https?:)?\/\//i)
    expect(html).not.toMatch(/<link\b/i)
    expect(html).not.toMatch(/<script[^>]*\ssrc=/i)
  })

  it('shows none of a bundle that does not check', async () => {
    const tampered = served.replace(/"artifact_digest":"[0-9a-f]{4}/, '"artifact_digest":"0000')
    expect(tampered).not.toBe(served)
    const { text, dom } = await open(historyPage(tampered, SAVED, NODE).html)
    expect(text).toContain('This history didn\'t verify, so this page shows none of it.')
    expect(text).toContain("Didn't verify: The answer's file is the bytes its digest names")
    expect(dom.window.document.querySelectorAll('.cvh-row').length).toBe(0)
  })

  it('shows a refusal as a refusal', async () => {
    const refusal = `${JSON.stringify(fixture.refused_unknown_pin)}\n`
    const { text } = await open(historyPage(refusal, SAVED, NODE).html)
    expect(text).toContain('The node declined to answer.')
    expect(text).toContain('coverage_unsatisfiable')
    expect(text).not.toContain('every checkpoint signature checks')
  })

  it('draws nothing from the bundle as markup', async () => {
    const hostile = `${JSON.stringify({ reason: '<img src=x onerror=alert(1)>' })}\n`
    const { dom } = await open(historyPage(hostile, SAVED, NODE).html)
    expect(dom.window.document.querySelector('#result img')).toBeNull()
  })
})

const serviceFixture = readFileSync(
  path.resolve(process.cwd(), '../crates/evidence-plugin/tests/fixtures/service_history_reply.json'),
  'utf8'
)

describe('the History page of a Service History, opened offline', () => {
  it('verifies the card inside, shows the counts as the node states them, and says what it did not check', async () => {
    const { html } = historyPage(serviceFixture, SAVED, NODE)
    expect(Buffer.from(embedded(html)).equals(Buffer.from(serviceFixture, 'utf8'))).toBe(true)
    const { text, requested } = await open(html)
    expect(text).toContain('Service History: exchanges served in each closed week')
    expect(text).toContain('all models: 12')
    expect(text).toContain('model a: withheld')
    expect(text).toContain('model b: fewer than 5')
    expect(text).toContain('A witness time-stamped these records')
    expect(requested).toEqual([])
  })

  // Re-encode an edited artifact as the node would have served it, digest recomputed.
  const reserve = async (edit: (artifact: Record<string, unknown>) => void) => {
    const reply = JSON.parse(serviceFixture) as Record<string, unknown>
    const artifact = JSON.parse(Buffer.from(reply.artifact as string, 'base64url').toString('utf8')) as Record<string, unknown>
    edit(artifact)
    const { createHash } = await import('node:crypto')
    const text = JSON.stringify(artifact)
    const out = { ...reply, artifact: Buffer.from(text).toString('base64url'), artifact_digest: createHash('sha256').update(text).digest('hex') }
    return JSON.stringify(out)
  }
  const jcsOf = (v: unknown): string =>
    Array.isArray(v)
      ? `[${v.map(jcsOf).join(',')}]`
      : v && typeof v === 'object'
        ? `{${Object.keys(v as object).sort().map((k) => `${JSON.stringify(k)}:${jcsOf((v as Record<string, unknown>)[k])}`).join(',')}}`
        : JSON.stringify(v)

  it('shows none of a Service History whose embedded card was changed', async () => {
    const forged = await reserve((a) => {
      ;(a.history_card as Record<string, unknown>).evidence_stream = 'another-log'
    })
    const { text } = await open(historyPage(forged, SAVED, NODE).html)
    expect(text).toContain('This history didn\'t verify, so this page shows none of it.')
    expect(text).not.toContain('all models: 12')
  })

  it('names the anchor mismatch when the card and its digest were changed together', async () => {
    const { createHash } = await import('node:crypto')
    const forged = await reserve((a) => {
      const card = a.history_card as Record<string, unknown>
      card.evidence_stream = 'another-log'
      a.history_card_digest = createHash('sha256').update(jcsOf(card)).digest('hex')
    })
    const { text } = await open(historyPage(forged, SAVED, NODE).html)
    expect(text).toContain('This history didn\'t verify, so this page shows none of it.')
    expect(text).not.toContain('all models: 12')
  })

  it('refuses an artifact that is not declared a Service History for its card', async () => {
    const forged = await reserve((a) => {
      a.declared = ['history_card']
    })
    const { text } = await open(historyPage(forged, SAVED, NODE).html)
    expect(text).toContain('This history didn\'t verify, so this page shows none of it.')
  })

  it('does not call a cell without a stated reason withheld below the floor', async () => {
    const forged = await reserve((a) => {
      const periods = (a.period_counts as { periods: { cells: Record<string, unknown>[] }[] }).periods
      delete periods[0].cells[1].suppressed
    })
    const { text } = await open(historyPage(forged, SAVED, NODE).html)
    expect(text).toContain('no count stated')
  })
})

describe('the sealed Settlement page', () => {
  it('is the page the node served, byte for byte', () => {
    const page = '<!doctype html><html><body><script type="application/json">{"a":1}</script></body></html>'
    const saved = sealedSettlementPage(page, SAVED)
    expect(saved.html).toBe(page)
    expect(saved.fileName).toBe('mesh-settlement-20261029T180000.html')
  })
})

// Bundles as the node serves them: JSON text. `provider` is the plugin's own
// provider route's bundle; `oneSided` and `both` are agent-action-capsule's
// strict vector (a producer-selected bundle) and composed/v1 vector (two
// copies that agree), which verify but which no viewer receipt module draws.
const provider = JSON.stringify(meshProviderSelected)
const oneSided = JSON.stringify(producerSelected)
const both = JSON.stringify(composedAgree)

/** WebCrypto with Ed25519 import refused, as a browser without it. */
const withoutEd25519 = {
  subtle: {
    digest: webcrypto.subtle.digest.bind(webcrypto.subtle),
    importKey: async () => {
      throw Object.assign(new Error('Ed25519 is not supported'), { name: 'NotSupportedError' })
    }
  },
  getRandomValues: webcrypto.getRandomValues.bind(webcrypto)
}

describe('the receipt page, opened offline', () => {
  it('checks the embedded receipt itself, draws the provider\'s receipt with the viewer\'s module and hands back the JSON byte for byte (#398)', async () => {
    const { html, fileName } = receiptPage({ kind: 'bundle', bundleText: provider }, 'ex-1', SAVED)
    expect(fileName).toBe('mesh-receipt-ex-1-20261029T180000.html')
    expect(Buffer.from(embedded(html)).equals(Buffer.from(provider, 'utf8'))).toBe(true)

    const { dom, requested, text } = await open(html)
    const doc = dom.window.document
    expect(doc.querySelector('#result p.warn')?.textContent).toBe("Receipt: this node's receipt only")
    expect(text).toMatch(/\d+ of 3 records in the receipt are tied to a signed checkpoint\./)
    expect(text).not.toContain('stamped by both')
    // The viewer's provider module draws it under the lines (capsule-viewer#390):
    // its own half, the amounts received and the time served, with no owner's title.
    const drawn = doc.querySelector('#result .receipt [data-module="capsuleviewer.receipt.provider/v0"]')
    expect(drawn?.querySelector('[data-provider="own-half"]')?.textContent).toContain(
      "This is this node's own record of its half of the exchange."
    )
    expect(drawn?.textContent).toContain('1,990 msat')
    expect(drawn?.textContent).toContain('2026-10-30T19:50:00 UTC')
    expect(doc.querySelector('#result .receipt h1, #result .receipt h2')).toBeNull()
    // A page for anyone: no owner's words.
    for (const owner of ['PRIVATE', 'Do not forward', 'your receipt']) expect(text).not.toContain(owner)
    expect(requested).toEqual([])
    expect((await savedBytes(dom)).equals(Buffer.from(provider, 'utf8'))).toBe(true)
  })

  it('draws a payer\'s deal receipt with the viewer\'s receipt, its top line once and first (#376)', async () => {
    const bundleText = JSON.stringify(meshPayerDeal)
    const { dom, requested, text } = await open(receiptPage({ kind: 'bundle', bundleText }, 'ex-5', SAVED).html)
    const doc = dom.window.document
    expect(doc.querySelector('#result p.warn')?.textContent).toBe("Receipt: this node's receipt only")
    // The viewer's receipt is drawn under the lines, its L0 region first.
    const top = doc.querySelector('#result .receipt [data-region="L0"]')?.textContent ?? ''
    expect(top).toContain(
      "Checked in this browser by the page's verifier (agent-action-capsule): graph closure (verified), interval coverage (not checked), per record membership (verified)."
    )
    expect(text.split("Checked in this browser by the page's verifier").length - 1).toBe(1)
    // A page for anyone: the viewer's "page" carrier, not the owner's copy
    // (capsule-viewer#395, #396; Sherlock2 on #378).
    expect(text).toContain(
      "This node's own record of this exchange, saved as a page for anyone to check. It is not the other side's copy."
    )
    for (const owner of ['PRIVATE', 'Do not forward', 'Tell your agent', 'your receipt']) {
      expect(text).not.toContain(owner)
    }
    expect(text).not.toContain('did not re-check')
    // No signed field carries the Mesh payer deal's amount, so no Amount card (capsule-viewer#391).
    expect(top).not.toContain('NOT PRESENT')
    // The plugin seals every deal on rail `lightning` (deal_records.rs RAIL), so
    // the viewer says no test money: it does only when every rail is simulated.
    expect(text).not.toContain('Test money')
    expect(doc.getElementById('cv-kit-css')).not.toBeNull()
    expect(requested).toEqual([])
    expect((await savedBytes(dom)).equals(Buffer.from(bundleText, 'utf8'))).toBe(true)
  })

  it.each([
    ['a producer-selected bundle', oneSided],
    ['two agreeing copies', both]
  ])('draws no receipt for %s no receipt module draws, and says so in the not-drawn lines', async (_name, bundleText) => {
    const { dom, text } = await open(receiptPage({ kind: 'bundle', bundleText }, 'ex-6', SAVED).html)
    const lines = [...dom.window.document.querySelectorAll('#result p')].map((p) => p.textContent)
    expect(lines).toEqual([...NOT_DRAWN_LINES])
    expect(dom.window.document.querySelector('#result p.muted')?.textContent).toBe(NOT_DRAWN_LINES[0])
    expect(dom.window.document.querySelector('#result .warn, #result .bad')).toBeNull()
    expect(dom.window.document.querySelector('#result .receipt')).toBeNull()
    expect(text).not.toContain('Receipt:')    // The lines name the page's own button, as the row's do (Sherlock2 on #398).
    expect(dom.window.document.getElementById('save-json')?.textContent).toBe('Save bundle')
  })

  it('shows none of a receipt that does not check', async () => {
    const tampered = JSON.parse(oneSided)
    tampered.records[0].capsule_id = 'f'.repeat(64)
    const { text } = await open(receiptPage({ kind: 'bundle', bundleText: JSON.stringify(tampered) }, 'ex-1', SAVED).html)
    expect(text).toContain('the receipt did not verify: do not rely on it')
    expect(text).not.toContain('Receipt:')
    expect(text).not.toContain('tied to a signed checkpoint')
  })

  it('draws none of a deal receipt that does not check', async () => {
    const tampered = JSON.parse(JSON.stringify(meshPayerDeal))
    tampered.records[0].capsule_id = 'f'.repeat(64)
    const { dom, text } = await open(receiptPage({ kind: 'bundle', bundleText: JSON.stringify(tampered) }, 'ex-7', SAVED).html)
    expect(text).toContain('the receipt did not verify: do not rely on it')
    expect(dom.window.document.querySelector('#result [data-region]')).toBeNull()
  })

  it('gives no verdict in a browser that cannot check Ed25519', async () => {
    const { text } = await open(receiptPage({ kind: 'bundle', bundleText: oneSided }, 'ex-1', SAVED).html, {
      crypto: withoutEd25519
    })
    expect(text).toContain("this browser can't check the receipt")
    expect(text).not.toContain('Receipt:')
  })

  it('refers to nothing outside itself', () => {
    const { html } = receiptPage({ kind: 'bundle', bundleText: oneSided }, 'ex-1', SAVED)
    expect(html).not.toMatch(/(?:src|href)\s*=\s*["']?(?:https?:)?\/\//i)
    expect(html).not.toMatch(/<link\b/i)
    expect(html).not.toMatch(/<script[^>]*\ssrc=/i)
  })

  it('says "no record" with the reason when there is no receipt, and holds no evidence', async () => {
    const { html } = receiptPage({ kind: 'no_record', why: NO_PAID_DEAL_WHY }, 'ex-3', SAVED)
    const { text, dom } = await open(html)
    expect(text).toContain('Receipt: no record')
    expect(text).toContain(`Its reason: ${NO_PAID_DEAL_WHY}`)
    expect(text).toContain('This page holds no evidence from the node.')
    expect(html).not.toContain('CapsulesSavedPage=')
    const note = JSON.parse((await savedBytes(dom)).toString('utf8'))
    expect(note).toEqual({ source: 'dashboard', case: 'no_record', why: NO_PAID_DEAL_WHY })
  })

  it('says "no receipt yet" with the node\'s own reason, drawn as text', async () => {
    const { dom, text } = await open(
      receiptPage({ kind: 'no_receipt_yet', why: '<img src=x onerror=alert(1)>' }, 'ex-4', SAVED).html
    )
    expect(text).toContain('No receipt yet')
    expect(text).toContain('Its reason: <img src=x onerror=alert(1)>')
    expect(dom.window.document.querySelector('#result img')).toBeNull()
  })

  it('names the file after a hostile exchange key only by its safe characters', () => {
    expect(receiptPage({ kind: 'no_record', why: 'x' }, '../a b<c>', SAVED).fileName).toBe(
      'mesh-receipt----a-b-c--20261029T180000.html'
    )
  })
})
