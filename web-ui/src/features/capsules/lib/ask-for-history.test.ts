import { ed25519 } from '@noble/curves/ed25519'
import { describe, expect, it } from 'vitest'
import type { EvidenceAskReply, EvidenceVerification } from '@/features/capsules/api/evidenceRequestClient'
import { ASK_DID_NOT_GO_THROUGH, refusalSigningBody } from '@/features/capsules/lib/ask-for-record'
import { formatExchangeTimestamp } from '@/features/capsules/lib/local-time'
import { historyNote, historyRefusalWords, judgeHistoryReply } from '@/features/capsules/lib/ask-for-history'

const ASKED_AT = '2026-10-22T10:00:00Z'
const SENT = 'f'.repeat(64)
const hex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
const PEER_SECRET = ed25519.utils.randomSecretKey()
const ANNOUNCED = hex(ed25519.getPublicKey(PEER_SECRET))

function signedRefusal(reason: string, secret = PEER_SECRET) {
  const refusal = { request_digest: SENT, reason, issued_at: '2026-10-22T10:00:02Z' }
  const sig = ed25519.sign(refusalSigningBody(refusal), secret)
  return { ...refusal, key_id: hex(ed25519.getPublicKey(secret)), sig: hex(sig) }
}

function reply(answer: unknown, verification: EvidenceVerification, announcedKeyId: string | null = ANNOUNCED): EvidenceAskReply {
  return { kind: 'answer', answer, verification, requestDigest: SENT, announcedKeyId, held: [] }
}

/** A note that isn't witnessed never reads as verified (evidencebook#209). */
function expectNeverVerified(note: ReturnType<typeof historyNote>) {
  expect(note?.verified).toBe(false)
  const all = `${note?.text} ${note?.checkedLine ?? ''} ${note?.detail ?? ''}`
  expect(all).not.toContain('✓')
  expect(all).not.toMatch(/checks out|verified/i)
}

describe('a history_card/2 ask', () => {
  it('says its count is a sample, not the size of the log', () => {
    const asked = { ...reply({}, { state: 'artifact', records: [], checkpoints: 12, witnessed: 1 }), derivation: 'history_card/2' } as EvidenceAskReply
    const outcome = judgeHistoryReply(asked, ASKED_AT)
    expect(outcome).toEqual({ kind: 'verified', at: ASKED_AT, checkpoints: 12, witness: 'witnessed', sampled: true })
    const note = historyNote(outcome)
    expect(note?.text).toContain('12 sampled checkpoints')
    expect(note?.detail).toContain('joined to the next by a proof that it extends the one before')
    expect(note?.detail).not.toContain('each extending the one before')
  })

  it('a history_card/1 answer keeps its own wording', () => {
    const asked = { ...reply({}, { state: 'artifact', records: [], checkpoints: 3, witnessed: 1 }), derivation: 'history_card/1' } as EvidenceAskReply
    expect(judgeHistoryReply(asked, ASKED_AT)).toEqual({ kind: 'verified', at: ASKED_AT, checkpoints: 3, witness: 'witnessed' })
  })
})

describe('judgeHistoryReply', () => {
  it('a witnessed history card is verified, with its checkpoint count and the witness', () => {
    const outcome = judgeHistoryReply(reply({}, { state: 'artifact', records: [], checkpoints: 3, witnessed: 2 }), ASKED_AT)
    expect(outcome).toEqual({ kind: 'verified', at: ASKED_AT, checkpoints: 3, witness: 'witnessed' })
    expect(historyNote(outcome)).toEqual({
      verified: true,
      witness: 'witnessed',
      text: '✓ Their history checks out · 3 checkpoints',
      checkedLine: `checked ${formatExchangeTimestamp(ASKED_AT)}`,
      detail:
        'Their history is verified: 3 checkpoints of their log, each signed with the key this node has for them and each extending the one before. A witness this node trusts holds their checkpoint.'
    })
    const one = judgeHistoryReply(reply({}, { state: 'artifact', records: [], checkpoints: 1, witnessed: 1 }), ASKED_AT)
    expect(historyNote(one)?.text).toBe('✓ Their history checks out · 1 checkpoint')
  })

  it('a history no configured witness vouches for checks against their own signatures only, never "verified"', () => {
    const outcome = judgeHistoryReply(reply({}, { state: 'artifact', records: [], checkpoints: 3, witnessed: 0 }), ASKED_AT)
    expect(outcome).toEqual({ kind: 'verified', at: ASKED_AT, checkpoints: 3, witness: 'unwitnessed' })
    const note = historyNote(outcome)
    expect(note).toEqual({
      verified: false,
      witness: 'unwitnessed',
      text: 'Their history checks against their own signatures only · 3 checkpoints',
      checkedLine: `checked ${formatExchangeTimestamp(ASKED_AT)}`,
      detail:
        '3 checkpoints of their log, each signed with the key this node has for them and each extending the one before. No witness this node trusts has vouched for that log, so it could be a private copy.'
    })
    expectNeverVerified(note)
  })

  it('a history checked with no witness configured says there was none to check it against', () => {
    const outcome = judgeHistoryReply(reply({}, { state: 'artifact', records: [], checkpoints: 2 }), ASKED_AT)
    expect(outcome).toEqual({ kind: 'verified', at: ASKED_AT, checkpoints: 2, witness: 'no_witness' })
    const note = historyNote(outcome)
    expect(note).toEqual({
      verified: false,
      witness: 'no_witness',
      text: 'Their history checks against their own signatures only · 2 checkpoints',
      checkedLine: `checked ${formatExchangeTimestamp(ASKED_AT)}`,
      detail:
        '2 checkpoints of their log, each signed with the key this node has for them and each extending the one before. This node has no witness configured to check it against, so it could be a private copy.'
    })
    expectNeverVerified(note)
  })

  it('a remembered history whose witness standing was not recorded says so, never "verified"', () => {
    const note = historyNote({ kind: 'verified', at: ASKED_AT, checkpoints: 4, witness: 'not_recorded' })
    expect(note).toEqual({
      verified: false,
      witness: 'not_recorded',
      text: 'Their history checked against their own signatures · 4 checkpoints',
      checkedLine: `checked ${formatExchangeTimestamp(ASKED_AT)}`,
      detail:
        'Checked against their own signatures: 4 checkpoints of their log, each signed with the key this node has for them and each extending the one before. Its witness standing was not recorded, so it could be a private copy; ask again to check it.'
    })
    expectNeverVerified(note)
  })

  it('a checked card whose checkpoint count the plugin didn’t give reads as unknown, never "0 checkpoints"', () => {
    const outcome = judgeHistoryReply(reply({}, { state: 'artifact', records: [], witnessed: 1 }), ASKED_AT)
    expect(outcome).toEqual({ kind: 'verified', at: ASKED_AT, checkpoints: null, witness: 'witnessed' })
    const note = historyNote(outcome)
    expect(note?.text).toBe('✓ Their history checks out')
    expect(note?.detail).toBe(
      'Their history is verified: the checkpoints of their log, each signed with the key this node has for them and each extending the one before. A witness this node trusts holds their checkpoint.'
    )
    expect(`${note?.text} ${note?.detail}`).not.toMatch(/\b0 checkpoints/)
    const unwitnessed = historyNote(judgeHistoryReply(reply({}, { state: 'artifact', records: [], witnessed: 0 }), ASKED_AT))
    expect(unwitnessed?.text).toBe('Their history checks against their own signatures only')
    expect(unwitnessed?.detail?.startsWith('The checkpoints of their log, each signed')).toBe(true)
  })

  it('a refusal signed with their announced key over our request is their signed refusal, in plain words', () => {
    const outcome = judgeHistoryReply(
      reply(signedRefusal('policy_declined'), { state: 'refusal', reason: 'policy_declined' }),
      ASKED_AT
    )
    expect(outcome).toEqual({ kind: 'refused', at: '2026-10-22T10:00:02Z', reason: 'policy_declined' })
    const note = historyNote(outcome)
    expect(note?.verified).toBe(true)
    expect(note?.text).toContain(historyRefusalWords('policy_declined'))
    expect(note?.text).not.toContain('policy_declined')
  })

  it('a refusal signed with any other key, or with no announced key, is a failed ask', () => {
    const forged = judgeHistoryReply(
      reply(signedRefusal('policy_declined', ed25519.utils.randomSecretKey()), { state: 'refusal', reason: 'policy_declined' }),
      ASKED_AT
    )
    expect(forged.kind).toBe('failed')
    const noKey = judgeHistoryReply(
      reply(signedRefusal('policy_declined'), { state: 'refusal', reason: 'policy_declined' }, null),
      ASKED_AT
    )
    expect(noKey.kind).toBe('failed')
  })

  it('anything the plugin could not verify, or no answer at all, fails and says why', () => {
    // A tool error is never shown raw: one plain sentence instead.
    const noAnswer = judgeHistoryReply({ kind: 'no_answer', message: '{"error":"HTTP 502"}' }, ASKED_AT)
    expect(noAnswer).toEqual({ kind: 'failed', at: ASKED_AT, detail: ASK_DID_NOT_GO_THROUGH, plain: true })
    expect(historyNote(noAnswer)).toEqual({ verified: false, text: ASK_DID_NOT_GO_THROUGH })
    const gone = judgeHistoryReply({ kind: 'no_answer', message: 'could not reach peer: no route' }, ASKED_AT)
    expect(historyNote(gone)?.text).toBe('That node isn’t on the mesh now, so it can’t be asked.')
    const unverified = judgeHistoryReply(reply({}, { state: 'not_evidence', why: 'a consistency proof does not hold' }), ASKED_AT)
    expect(historyNote(unverified)).toEqual({
      verified: false,
      text: 'Their history is not verified: their reply did not verify: a consistency proof does not hold'
    })
    expect(judgeHistoryReply(reply({}, { state: 'no_announced_key' }), ASKED_AT).kind).toBe('failed')
    expect(judgeHistoryReply(reply({}, { state: 'unknown' }), ASKED_AT).kind).toBe('failed')
  })

  it('never echoes a refusal token it has no words for', () => {
    expect(historyRefusalWords('made_up_by_the_peer')).not.toContain('made_up')
  })
})
