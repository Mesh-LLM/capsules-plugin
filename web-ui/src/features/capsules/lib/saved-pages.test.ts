import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
import { SETTLEMENT_REFUSAL_WORDS, historyPage, settlementPage } from '@/features/capsules/lib/saved-pages'
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

  it('shows what this node shares, from the settings the node reported', async () => {
    const { text } = await open(historyPage(served, SAVED, NODE).html)
    expect(text).toContain('What this node shares')
    expect(text).toContain('With anyone: the Service History.')
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
