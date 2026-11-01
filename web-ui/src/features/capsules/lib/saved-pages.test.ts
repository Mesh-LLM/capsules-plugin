import { webcrypto } from 'node:crypto'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  NO_PAID_DEAL_WHY,
  SETTLEMENT_REFUSAL_WORDS,
  historyPage,
  receiptPage,
  settlementPage
} from '@/features/capsules/lib/saved-pages'
import composedAgree from '@/features/capsules/lib/receipt-fixtures/composed-agree.bundle.json'
import producerSelected from '@/features/capsules/lib/receipt-fixtures/producer-selected.bundle.json'
import { embeddedBundle as embedded, openSavedPage as open, savedBytes } from '@/lib/test/open-saved-page'

const fixture = JSON.parse(
  readFileSync(path.resolve(process.cwd(), '../crates/evidence-plugin/tests/fixtures/evidence_answers_5d2d102.json'), 'utf8')
) as Record<string, Record<string, unknown>>
// The bytes a node served: the reply as the node wrote it.
const served = `${JSON.stringify(fixture.history_card)}\n`
const SAVED = '2026-10-29T18:00:00Z'

describe('the History page, opened offline', () => {
  it('verifies the embedded answer itself and hands back the JSON byte for byte', async () => {
    const { html } = historyPage(served, SAVED)
    expect(Buffer.from(embedded(html)).equals(Buffer.from(served, 'utf8'))).toBe(true)

    const { dom, requested, text } = await open(html)
    expect(text).toContain('Checked against the node’s own key when this page opened: the history card matches its digest, and every checkpoint is signed by key')
    // Never the pass style: this page checks no witness receipt.
    expect(dom.window.document.querySelector('p.ok')).toBeNull()
    expect(dom.window.document.querySelector('p.warn')?.textContent).toContain('No witness receipt is checked here')
    expect(text).toContain('compare that key with the node’s published commitment')
    // evidencebook#209: a chain that checks only against its holder's key
    // says so on the line that says it was checked.
    expect(text).toContain('No witness receipt is checked here, so this could be a private copy of the node’s log')
    expect(text).not.toContain('unchanged')
    expect(text).toContain('Not checked: That this key is the node’s')
    expect(text).toMatch(/Checked: All \d+ checkpoints verify/)
    expect(text).toContain('Not checked: Witness receipts')
    expect(requested).toEqual([])

    expect((await savedBytes(dom)).equals(Buffer.from(served, 'utf8'))).toBe(true)
  })

  it('refers to nothing outside itself', () => {
    const { html } = historyPage(served, SAVED)
    expect(html).not.toMatch(/(?:src|href)\s*=\s*["']?(?:https?:)?\/\//i)
    expect(html).not.toMatch(/<link\b/i)
    expect(html).not.toMatch(/<script[^>]*\ssrc=/i)
  })

  it('shows none of a bundle that does not check', async () => {
    const tampered = served.replace(/"artifact_digest":"[0-9a-f]{4}/, '"artifact_digest":"0000')
    expect(tampered).not.toBe(served)
    const { text } = await open(historyPage(tampered, SAVED).html)
    expect(text).toContain('could not check its answer, so it shows none of it')
    expect(text).toContain('Failed: The artifact is not the bytes its digest names')
    expect(text).not.toContain('The log, checkpoint by checkpoint')
  })

  it('shows a refusal as a refusal', async () => {
    const refusal = `${JSON.stringify(fixture.refused_unknown_pin)}\n`
    const { text } = await open(historyPage(refusal, SAVED).html)
    expect(text).toContain('The node declined to answer')
    expect(text).not.toContain('matches its digest')
  })

  it('draws nothing from the bundle as markup', async () => {
    const hostile = `${JSON.stringify({ reason: '<img src=x onerror=alert(1)>' })}\n`
    const { dom } = await open(historyPage(hostile, SAVED).html)
    expect(dom.window.document.querySelector('#result img')).toBeNull()
  })
})

const serviceFixture = readFileSync(
  path.resolve(process.cwd(), '../crates/evidence-plugin/tests/fixtures/service_history_reply.json'),
  'utf8'
)

describe('the History page of a Service History, opened offline', () => {
  it('verifies the card inside, shows the counts as the node states them, and says what it did not check', async () => {
    const { html } = historyPage(serviceFixture, SAVED, 'service_history')
    expect(Buffer.from(embedded(html)).equals(Buffer.from(serviceFixture, 'utf8'))).toBe(true)
    const { text, requested } = await open(html)
    expect(text).toContain('Service History')
    expect(text).toContain('the history card inside the Service History matches its digest')
    expect(text).toContain('Checked: The history card inside matches its digest.')
    expect(text).toContain('Not checked: The counts were not checked')
    expect(text).toContain('all models: 12')
    expect(text).toContain('withheld (below the floor)')
    expect(text).toContain('withheld (showing it would let a count under the floor be worked out)')
    expect(text).toContain('Not checked: Witness receipts')
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
    const { text } = await open(historyPage(forged, SAVED, 'service_history').html)
    expect(text).toContain('could not check its answer, so it shows none of it')
    expect(text).toContain('Failed: The history card inside is not the bytes its digest names')
    expect(text).not.toContain('all models: 12')
  })

  it('names the anchor mismatch when the card and its digest were changed together', async () => {
    const { createHash } = await import('node:crypto')
    const forged = await reserve((a) => {
      const card = a.history_card as Record<string, unknown>
      card.evidence_stream = 'another-log'
      a.history_card_digest = createHash('sha256').update(jcsOf(card)).digest('hex')
    })
    const { text } = await open(historyPage(forged, SAVED, 'service_history').html)
    expect(text).toContain('Failed: The history card inside names another anchor or log than the answer')
    expect(text).not.toContain('all models: 12')
  })

  it('refuses an artifact that is not declared a Service History for its card', async () => {
    const forged = await reserve((a) => {
      a.declared = ['history_card']
    })
    const { text } = await open(historyPage(forged, SAVED, 'service_history').html)
    expect(text).toContain('Failed: The artifact is not a Service History for the card inside it')
  })

  it('does not call a cell without a stated reason withheld below the floor', async () => {
    const forged = await reserve((a) => {
      const periods = (a.period_counts as { periods: { cells: Record<string, unknown>[] }[] }).periods
      delete periods[0].cells[1].suppressed
    })
    const { text } = await open(historyPage(forged, SAVED, 'service_history').html)
    expect(text).toContain('no count stated')
  })
})

describe('the Settlement page, opened offline', () => {
  it('says plainly it holds no evidence from the node, and hands back its note byte for byte', async () => {
    const { html } = settlementPage(SAVED)
    const json = JSON.parse(new TextDecoder().decode(embedded(html))) as Record<string, string>
    expect(json).toEqual({ source: 'dashboard', reason: 'no_terms_pack', words: SETTLEMENT_REFUSAL_WORDS })
    expect(JSON.stringify(json)).not.toContain('mesh-settlement-report-refusal')
    const { dom, text, requested } = await open(html)
    expect(text).toContain('No report: this page holds no evidence from the node.')
    expect(text).toContain(SETTLEMENT_REFUSAL_WORDS)
    expect(text).toContain('It is not from the node')
    expect(requested).toEqual([])

    expect((await savedBytes(dom)).equals(Buffer.from(embedded(html)))).toBe(true)
  })

  it('shows nothing from a note that is not the one it writes', async () => {
    const { html } = settlementPage(SAVED)
    const forged = html.replace(
      /(id="mesh-bundle"[^>]*>)[^<]*</,
      `$1${Buffer.from('{"source":"node","reason":"all_good","words":"All settled."}').toString('base64')}<`
    )
    const { text } = await open(forged)
    expect(text).toContain('could not read its own note, so it shows nothing')
    expect(text).not.toContain('All settled.')

    // Only the words changed: source and reason are still the dashboard's.
    const reworded = html.replace(
      /(id="mesh-bundle"[^>]*>)[^<]*</,
      `$1${Buffer.from('{"source":"dashboard","reason":"no_terms_pack","words":"All settled."}').toString('base64')}<`
    )
    const { text: rewordedText } = await open(reworded)
    expect(rewordedText).toContain('could not read its own note, so it shows nothing')
    expect(rewordedText).not.toContain('All settled.')
  })
})

// The receipt routes' bundles, as the node serves them: JSON text. The
// fixtures are agent-action-capsule's strict vector (a producer-selected
// bundle, one side's receipt) and composed/v1 vector (two copies that agree).
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
  it('checks the embedded receipt itself and hands back the JSON byte for byte', async () => {
    const { html, fileName } = receiptPage({ kind: 'bundle', bundleText: oneSided }, 'ex-1', SAVED)
    expect(fileName).toBe('mesh-receipt-ex-1-20261029T180000.html')
    expect(Buffer.from(embedded(html)).equals(Buffer.from(oneSided, 'utf8'))).toBe(true)

    const { dom, requested, text } = await open(html)
    expect(dom.window.document.querySelector('#result p.warn')?.textContent).toBe('Receipt: your receipt only')
    expect(text).toMatch(/\d+ of \d+ records in the receipt are tied to a signed checkpoint\./)
    expect(text).not.toContain('stamped by both')
    expect(requested).toEqual([])
    expect((await savedBytes(dom)).equals(Buffer.from(oneSided, 'utf8'))).toBe(true)
  })

  it('says "stamped by both" only for two copies that agree', async () => {
    const { dom } = await open(receiptPage({ kind: 'bundle', bundleText: both }, 'ex-2', SAVED).html)
    expect(dom.window.document.querySelector('#result p.ok')?.textContent).toBe('Receipt: stamped by both')
  })

  it('shows none of a receipt that does not check', async () => {
    const tampered = JSON.parse(oneSided)
    tampered.records[0].capsule_id = 'f'.repeat(64)
    const { text } = await open(receiptPage({ kind: 'bundle', bundleText: JSON.stringify(tampered) }, 'ex-1', SAVED).html)
    expect(text).toContain('the receipt did not verify: do not rely on it')
    expect(text).not.toContain('Receipt:')
    expect(text).not.toContain('tied to a signed checkpoint')
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
