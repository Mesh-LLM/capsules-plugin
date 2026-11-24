import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
import { base64urlToBytes, cardPositions, parseReaderWitnesses, verifyHistoryReply } from '@/features/capsules/lib/history-verify'

// A real reply from a corpus node (crates/evidence-plugin/tests/fixtures).
const fixture = JSON.parse(
  readFileSync(path.resolve(process.cwd(), '../crates/evidence-plugin/tests/fixtures/evidence_answers_5d2d102.json'), 'utf8')
) as Record<string, Record<string, unknown>>

const card = fixture.history_card

// A real `history_card/2` reply: a corpus node with 40 checkpoints, so the card
// samples positions and skips the checkpoints between them
// (crates/evidence-plugin/tests/fixtures/history_card_2_reply.json).
const card2 = JSON.parse(
  readFileSync(path.resolve(process.cwd(), '../crates/evidence-plugin/tests/fixtures/history_card_2_reply.json'), 'utf8')
) as Record<string, unknown>
const artifactOf = (reply: Record<string, unknown>) =>
  JSON.parse(new TextDecoder().decode(base64urlToBytes(reply.artifact as string)!)) as Record<string, unknown>

const encodeArtifact = async (artifact: unknown) => {
  const bytes = new TextEncoder().encode(JSON.stringify(artifact))
  const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), (b) => b.toString(16).padStart(2, '0')).join('')
  return { artifact: btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''), artifact_digest: digest }
}

const failed = (v: Awaited<ReturnType<typeof verifyHistoryReply>>) => v.checks.find((c) => c.status === 'fail')?.id

describe('verifyHistoryReply', () => {
  it('verifies a real history card with more than one checkpoint, and lists what it did not run', async () => {
    const verdict = await verifyHistoryReply(JSON.stringify(card))
    expect(verdict.checks.filter((c) => c.status === 'fail')).toEqual([])
    expect(verdict.verified).toBe(true)
    expect(verdict.checkpoints.length).toBeGreaterThan(1)
    expect(verdict.checks.filter((c) => c.status === 'not_run').map((c) => c.id)).toEqual([
      'witness_receipts',
      'envelope_signature',
      'key_is_nodes',
      'request_binding'
    ])
  })

  it('refuses an artifact that is not the bytes its digest names', async () => {
    const v = await verifyHistoryReply(JSON.stringify({ ...card, artifact_digest: '0'.repeat(64) }))
    expect(v.verified).toBe(false)
    expect(failed(v)).toBe('artifact_digest')
  })

  it('refuses a consistency proof that was changed', async () => {
    const artifact = artifactOf(card) as { history: { consistency_from_previous: string | null }[] }
    const entry = artifact.history[1]
    const proof = entry.consistency_from_previous!
    entry.consistency_from_previous = proof.slice(0, -2) + (proof.endsWith('00') ? '01' : '00')
    const v = await verifyHistoryReply(JSON.stringify({ ...card, ...(await encodeArtifact(artifact)) }))
    expect(v.verified).toBe(false)
    expect(failed(v)).toBe('consistency')
  })

  it('refuses a consistency proof whose right peaks were emptied or cut', async () => {
    const artifact = artifactOf(card) as { history: { consistency_from_previous: string | null }[] }
    // [from, to, paths, right]: with a one-hash `right`, dropping it leaves the proof well-formed.
    let changed = 0
    for (const entry of artifact.history.slice(1)) {
      const bytes = Buffer.from(entry.consistency_from_previous!, 'hex')
      // The proof ends with the `right` array: 0x8N then N 32-byte hashes (0x5820 prefix each).
      const at = bytes.lastIndexOf(Buffer.from([0x58, 0x20]))
      if (at < 0) continue
      const rightCount = (bytes.length - at) / 34
      if (!Number.isInteger(rightCount) || rightCount < 1) continue
      const headerAt = at - 34 * (rightCount - 1) - 1
      if ((bytes[headerAt] & 0xe0) !== 0x80) continue
      const cut = Buffer.concat([bytes.subarray(0, headerAt), Buffer.from([0x80])])
      entry.consistency_from_previous = cut.toString('hex')
      changed++
      break
    }
    expect(changed).toBe(1)
    const v = await verifyHistoryReply(JSON.stringify({ ...card, ...(await encodeArtifact(artifact)) }))
    expect(v.verified).toBe(false)
    expect(failed(v)).toBe('consistency')
  })

  it('refuses a reply that names no anchor', async () => {
    const { anchor: _anchor, ...withoutAnchor } = card
    const v = await verifyHistoryReply(JSON.stringify(withoutAnchor))
    expect(v.verified).toBe(false)
    expect(failed(v)).toBe('anchor')
    const v2 = await verifyHistoryReply(JSON.stringify({ ...card, anchor: null }))
    expect(failed(v2)).toBe('anchor')
  })

  it('names the key the checkpoints were checked under', async () => {
    const v = await verifyHistoryReply(JSON.stringify(card))
    expect(v.keyId).toBe(card.responder)
  })

  it('refuses a checkpoint that was changed', async () => {
    const artifact = artifactOf(card) as { history: { checkpoint: string }[] }
    const cp = artifact.history[0].checkpoint
    artifact.history[0].checkpoint = cp.slice(0, -2) + (cp.endsWith('00') ? '01' : '00')
    const v = await verifyHistoryReply(JSON.stringify({ ...card, ...(await encodeArtifact(artifact)) }))
    expect(v.verified).toBe(false)
    expect(failed(v)).toBe('checkpoints')
    // A changed signature still reads as a failed check, never as a format rejection.
    expect(v.checks.find((c) => c.status === 'fail')?.detail).toBe('Checkpoint 1 does not verify.')
  })

  // A one-checkpoint statement signed with a throwaway key (32 zero bytes seed) whose issued_at is "yesterday": the signature
  // is valid, the format is not. Made with cll's own signing path, the claims then rewritten and re-signed.
  const SIGNED_BAD_ISSUED_AT = 'd2845868a4012703781f6170706c69636174696f6e2f636c6c2d636865636b706f696e742b63626f720458203b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da290fa2016d6e656761746976652d74657374026d6e656761746976652d74657374a0587fa6646b696e646e636c6c2d636865636b706f696e74686c6f675f73697a6501696973737565645f61746979657374657264617969707265765f73697a65006a636f6d6d69746d656e7458238158204635e1fa62a599a7880a8d14a56f720a1d40f6e5448ab5a5e39bedc8bd87fa8e6f707265765f636f6d6d69746d656e74405840359b4358ada5e6062fbd8a9575ebd497171a2849cd0977ac97c769f7c283070d329ccb5c28954e4c53edb0f4095d077502496dfb094750daecb54acc8051a500'

  const replaceFirstCheckpoint = async (checkpointHex: string) => {
    const artifact = artifactOf(card) as { history: { checkpoint: string }[] }
    artifact.history[0].checkpoint = checkpointHex
    return verifyHistoryReply(JSON.stringify({ ...card, ...(await encodeArtifact(artifact)) }))
  }
  const failDetail = (v: Awaited<ReturnType<typeof verifyHistoryReply>>) => v.checks.find((c) => c.status === 'fail')?.detail

  // The key that signed SIGNED_BAD_ISSUED_AT (hex of the header's kid).
  const THROWAWAY_KEY = '3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29'

  it('names the field when a checkpoint signed by the key that answered is refused for the format of its issued_at', async () => {
    const artifact = artifactOf(card) as { history: { checkpoint: string }[] }
    artifact.history[0].checkpoint = SIGNED_BAD_ISSUED_AT
    const v = await verifyHistoryReply(JSON.stringify({ ...card, responder: THROWAWAY_KEY, ...(await encodeArtifact(artifact)) }))
    expect(v.verified).toBe(false)
    expect(failed(v)).toBe('checkpoints')
    expect(failDetail(v)).toBe('Checkpoint 1: `issued_at` is not in the expected format (a format rejection, not a failed signature).')
  })

  it('does not call a malformed issued_at a format rejection when another key signed it', async () => {
    // Anyone can sign a checkpoint with their own key: the signature holds, but not under the key that answered.
    const v = await replaceFirstCheckpoint(SIGNED_BAD_ISSUED_AT)
    expect(failed(v)).toBe('checkpoints')
    expect(failDetail(v)).toBe('Checkpoint 1 is not signed by the key that answered.')
  })

  it('shows the signature failure, never the format text, for a malformed issued_at with a tampered signature', async () => {
    // The last signature byte is flipped, so both the format and the signature are wrong: the signature failure wins.
    const bytes = Buffer.from(SIGNED_BAD_ISSUED_AT, 'hex')
    bytes[bytes.length - 1] ^= 0xff
    const v = await replaceFirstCheckpoint(bytes.toString('hex'))
    expect(failed(v)).toBe('checkpoints')
    expect(failDetail(v)).toBe('Checkpoint 1 does not verify.')
  })

  // The oldest checkpoint of a real demo node's log (position 0: log_size 63, prev_size 0, issued_at with milliseconds
  // "2026-10-02T02:40:00.000Z"), signed by checkpointed-local-log 0.2.0 or earlier. Its signature holds, but its claims are in
  // insertion order (kind, log_size, commitment, prev_size, prev_commitment, issued_at), not deterministic CBOR (issue #327).
  const LEGACY_ORDER_CHECKPOINT =
    'd28458a1a4012703781f6170706c69636174696f6e2f636c6c2d636865636b706f696e742b63626f720458205631608d05e1eee382e519abd6e93730a091a7334cbd5c33cb07f92af000b0310fa201782763617073756c652d656d69742d6d6573682f753232372d6335653761663038643833353635383202782a63617073756c652d656d69742d6d6573682f753232372d63356537616630386438333536353832233633a05890a6646b696e646e636c6c2d636865636b706f696e74686c6f675f73697a65183f6a636f6d6d69746d656e74582381582030a982d56a27997e5db6c793b428d6937fbebec892a8e335054963feb9765eba69707265765f73697a65006f707265765f636f6d6d69746d656e7440696973737565645f61747818323032362d31302d30325430323a34303a30302e3030305a5840e8603e44cfbc2a39990e912eb1071757c04fc3f16689b790ccae9b1d911b3f39df07bd3d1bd524b3c22bab927fa7a0a167c22d42b858f6eb016bd05c4c73e706'
  const LEGACY_KEY = '5631608d05e1eee382e519abd6e93730a091a7334cbd5c33cb07f92af000b031'

  it('refuses a checkpoint whose claims are not in canonical order, and says its signature holds', async () => {
    const artifact = artifactOf(card) as { history: { checkpoint: string }[] }
    artifact.history[0].checkpoint = LEGACY_ORDER_CHECKPOINT
    const v = await verifyHistoryReply(JSON.stringify({ ...card, responder: LEGACY_KEY, ...(await encodeArtifact(artifact)) }))
    expect(v.verified).toBe(false)
    expect(failed(v)).toBe('checkpoints')
    expect(failDetail(v)).toContain('Checkpoint 1 is refused for its non-canonical encoding')
    expect(failDetail(v)).toContain('checkpointed-local-log 0.2.0 and earlier')
    expect(failDetail(v)).toContain('The signature itself holds under the key that answered.')
  })

  it('does not say a legacy-order checkpoint\'s signature holds when another key answered', async () => {
    const v = await replaceFirstCheckpoint(LEGACY_ORDER_CHECKPOINT)
    expect(failed(v)).toBe('checkpoints')
    expect(failDetail(v)).toBe('Checkpoint 1 does not verify.')
  })

  it('shows the signature failure, not the non-canonical text, for a legacy-order checkpoint with a tampered signature', async () => {
    const bytes = Buffer.from(LEGACY_ORDER_CHECKPOINT, 'hex')
    bytes[bytes.length - 1] ^= 0xff
    const artifact = artifactOf(card) as { history: { checkpoint: string }[] }
    artifact.history[0].checkpoint = bytes.toString('hex')
    const v = await verifyHistoryReply(JSON.stringify({ ...card, responder: LEGACY_KEY, ...(await encodeArtifact(artifact)) }))
    expect(failDetail(v)).toBe('Checkpoint 1 does not verify.')
  })

  it('shows the signature failure for a malformed issued_at edited after signing', async () => {
    const artifact = artifactOf(card) as { history: { checkpoint: string }[] }
    // The T of the first checkpoint's issued_at becomes a space: the same length, so still valid CBOR, but no longer RFC 3339,
    // and the signature no longer covers the bytes.
    const bytes = Buffer.from(artifact.history[0].checkpoint, 'hex')
    const at = bytes.toString('latin1').search(/\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d/)
    expect(at).toBeGreaterThan(0)
    bytes[at + 10] = 0x20
    const v = await replaceFirstCheckpoint(bytes.toString('hex'))
    expect(failed(v)).toBe('checkpoints')
    expect(failDetail(v)).toBe('Checkpoint 1 does not verify.')
  })

  it('refuses a card whose checkpoints were signed by another key', async () => {
    const v = await verifyHistoryReply(JSON.stringify({ ...card, responder: 'ab'.repeat(32) }))
    expect(v.verified).toBe(false)
    expect(failed(v)).toBe('checkpoints')
  })

  it('refuses a card with a checkpoint dropped from the middle', async () => {
    const artifact = artifactOf(card) as { history: unknown[] }
    artifact.history.splice(1, 1)
    const v = await verifyHistoryReply(JSON.stringify({ ...card, ...(await encodeArtifact(artifact)) }))
    expect(v.verified).toBe(false)
  })

  it('shows a signed refusal as a refusal, never as a verified card', async () => {
    const v = await verifyHistoryReply(JSON.stringify(fixture.refused_unknown_pin))
    expect(v.kind).toBe('refused')
    expect(v.verified).toBe(false)
    expect(v.reason).toBeTruthy()
  })

  it('does not read what is not JSON', async () => {
    const v = await verifyHistoryReply('not json')
    expect(v.kind).toBe('unreadable')
    expect(v.verified).toBe(false)
  })

  describe('a history_card/2', () => {
    type Entry = { position: number; checkpoint: string; consistency_from_previous: string | null }
    const art2 = () => artifactOf(card2) as { window: number; history: Entry[] }
    const reply2 = async (artifact: unknown) => JSON.stringify({ ...card2, ...(await encodeArtifact(artifact)) })

    it('verifies a card that skips checkpoints, and names what it checked', async () => {
      const artifact = art2()
      expect(artifact.history.length).toBeLessThan(40)
      expect(artifact.history.map((e) => e.position)).toEqual(cardPositions(39, artifact.window))
      const verdict = await verifyHistoryReply(JSON.stringify(card2))
      expect(verdict.checks.filter((c) => c.status === 'fail')).toEqual([])
      expect(verdict.verified).toBe(true)
      expect(verdict.form).toBe('history_card')
      expect(verdict.checkpoints).toHaveLength(artifact.history.length)
      expect(verdict.checks.find((c) => c.id === 'chain')?.detail).toContain('history_card/2')
    })

    it('lists the positions the spec lists', () => {
      expect(cardPositions(0, 16)).toEqual([0])
      expect(cardPositions(3, 1)).toEqual([0, 1, 2, 3])
      expect(cardPositions(100, 4)).toEqual([0, 36, 68, 84, 92, 96, 97, 98, 99, 100])
    })

    it('refuses a card with a sampled position missing', async () => {
      const artifact = art2()
      artifact.history.splice(1, 1)
      const v = await verifyHistoryReply(await reply2(artifact))
      expect(v.verified).toBe(false)
      expect(failed(v)).toBe('chain')
    })

    it('refuses a card whose window or positions were changed', async () => {
      const wider = art2()
      wider.window = 20
      expect(failed(await verifyHistoryReply(await reply2(wider)))).toBe('chain')
      const outOfRange = art2()
      outOfRange.window = 65
      expect(failed(await verifyHistoryReply(await reply2(outOfRange)))).toBe('readable')
      const moved = art2()
      moved.history[2].position += 1
      expect(failed(await verifyHistoryReply(await reply2(moved)))).toBe('chain')
    })

    it('refuses a proof between sampled entries that was changed', async () => {
      const artifact = art2()
      const entry = artifact.history[1]
      const proof = entry.consistency_from_previous!
      entry.consistency_from_previous = proof.slice(0, -2) + (proof.endsWith('00') ? '01' : '00')
      const v = await verifyHistoryReply(await reply2(artifact))
      expect(v.verified).toBe(false)
      expect(failed(v)).toBe('consistency')
    })

    it('refuses neighbours that do not follow each other, and a first entry that is not the start', async () => {
      // Positions 38 and 39 sit next to each other in the card: swap their checkpoints.
      const artifact = art2()
      const [a, b] = [artifact.history.length - 2, artifact.history.length - 1]
      const swapped = artifact.history[a].checkpoint
      artifact.history[a].checkpoint = artifact.history[b].checkpoint
      artifact.history[b].checkpoint = swapped
      const v = await verifyHistoryReply(await reply2(artifact))
      expect(v.verified).toBe(false)
      expect(['chain', 'consistency']).toContain(failed(v))
      const dropped = art2()
      dropped.history.shift()
      expect(failed(await verifyHistoryReply(await reply2(dropped)))).toBe('chain')
    })

    it('refuses a first entry that carries a proof, or none', async () => {
      for (const proof of ['00', undefined]) {
        const artifact = art2() as { history: { consistency_from_previous?: string | null }[] }
        if (proof === undefined) delete artifact.history[0].consistency_from_previous
        else artifact.history[0].consistency_from_previous = proof
        const v = await verifyHistoryReply(await reply2(artifact))
        expect(v.verified).toBe(false)
        // A missing member is an entry that is not the card's; a proof on the first entry is no proof.
        expect(failed(v)).toBe(proof === undefined ? 'readable' : 'consistency')
      }
      const one = artifactOf(card) as { history: { consistency_from_previous: string | null }[] }
      one.history[0].consistency_from_previous = '00'
      expect(failed(await verifyHistoryReply(JSON.stringify({ ...card, ...(await encodeArtifact(one)) })))).toBe('consistency')
    })

    it('refuses an entry whose position is missing, not an integer, negative or repeated', async () => {
      for (const change of [
        (e: Record<string, unknown>[]) => delete e[3].position,
        (e: Record<string, unknown>[]) => (e[3].position = 7.5),
        (e: Record<string, unknown>[]) => (e[3].position = -1),
        (e: Record<string, unknown>[]) => (e[3].position = e[2].position)
      ]) {
        const artifact = art2() as unknown as { history: Record<string, unknown>[] }
        change(artifact.history)
        const v = await verifyHistoryReply(await reply2(artifact))
        expect(v.verified).toBe(false)
        expect(['chain', 'readable']).toContain(failed(v))
      }
    })

    it('refuses an entry without a receipts list, an extra member, or a subject that does not name the log', async () => {
      const noReceipts = art2() as unknown as { history: Record<string, unknown>[] }
      delete noReceipts.history[1].receipts
      expect(failed(await verifyHistoryReply(await reply2(noReceipts)))).toBe('readable')
      const extra = art2() as unknown as { history: Record<string, unknown>[] }
      extra.history[1].note = 'x'
      expect(failed(await verifyHistoryReply(await reply2(extra)))).toBe('readable')
      const otherSubject = art2() as unknown as { subject: unknown }
      otherSubject.subject = { record: 'ab'.repeat(32) }
      expect(failed(await verifyHistoryReply(await reply2(otherSubject)))).toBe('readable')
    })

    it('lists the window boundaries', () => {
      expect(cardPositions(1, 1)).toEqual([0, 1])
      // Window 64 at 200 covers 137 to 200; 136 is the sample 200 - 64, and 135 is neither.
      const at200 = cardPositions(200, 64)
      expect(at200).toContain(136)
      expect(at200).toContain(137)
      expect(at200).not.toContain(135)
      // Below the window: 0 and the samples 200 - 128 and 200 - 64.
      expect(at200.filter((p) => p < 137)).toEqual([0, 72, 136])
    })

    it('refuses a history_card/1 card named as a history_card/2', async () => {
      const v = await verifyHistoryReply(JSON.stringify({ ...card, derivation: 'history_card/2' }))
      expect(v.verified).toBe(false)
      expect(failed(v)).toBe('readable')
    })
  })
})

// A history_card/2 of a 40-checkpoint log whose checkpoints each carry a real receipt, minted with the
// plugin's own witness code under the key of seed 21 repeated 32 times (`evidence_answer.rs`,
// `the_witnessed_history_card_2_reply_is_the_golden_fixture`).
const witnessed = JSON.parse(
  readFileSync(path.resolve(process.cwd(), '../crates/evidence-plugin/tests/fixtures/history_card_2_witnessed.json'), 'utf8')
) as Record<string, unknown>
const SPKI_PREFIX = '302a300506032b6570032100'
const WITNESS_KEY = SPKI_PREFIX + 'd54207da194977dcf46adbfec2bc2e75b52d5a8a42184fedfdc00024f0e3e8da'
const otherKey = SPKI_PREFIX + '11'.repeat(32)
const readerList = (key: string) => ({ witnesses: [{ name: 'the witness', keys: [key] }] })
const witnessCheck = (v: Awaited<ReturnType<typeof verifyHistoryReply>>) => v.checks.find((c) => c.id === 'witness_receipts')!
const receiptsOf = (reply: Record<string, unknown>) => reply.witness_receipts as { checkpoint: string; witness: Record<string, unknown> }[]

describe('the witness receipts check', () => {
  it('passes a real receipt for the anchor under a key the reader supplied', async () => {
    const v = await verifyHistoryReply(JSON.stringify(witnessed), readerList(WITNESS_KEY))
    expect(v.verified).toBe(true)
    expect(witnessCheck(v).status).toBe('pass')
    expect(witnessCheck(v).detail).toContain('the witness')
  })

  it('does not run the check with no reader keys, and never passes it', async () => {
    for (const keys of [undefined, { witnesses: [] }]) {
      const v = await verifyHistoryReply(JSON.stringify(witnessed), keys)
      expect(v.verified).toBe(true)
      expect(witnessCheck(v).status).toBe('not_run')
    }
  })

  it('fails a receipt that no supplied key verifies', async () => {
    const v = await verifyHistoryReply(JSON.stringify(witnessed), readerList(otherKey))
    expect(v.verified).toBe(false)
    expect(witnessCheck(v).status).toBe('fail')
  })

  it('fails a receipt whose entry is not the one the anchor checkpoint states', async () => {
    const reply = structuredClone(witnessed)
    const anchor = (reply.anchor as { digest: string }).digest
    const mine = receiptsOf(reply).find((r) => r.checkpoint === anchor)!
    mine.witness.entry_hash = '0'.repeat(64)
    const v = await verifyHistoryReply(JSON.stringify(reply), readerList(WITNESS_KEY))
    expect(witnessCheck(v).status).toBe('fail')
  })

  it('counts only the anchor checkpoint’s receipts', async () => {
    const reply = structuredClone(witnessed)
    const anchor = (reply.anchor as { digest: string }).digest
    reply.witness_receipts = receiptsOf(reply).filter((r) => r.checkpoint !== anchor)
    const v = await verifyHistoryReply(JSON.stringify(reply), readerList(WITNESS_KEY))
    expect(v.verified).toBe(true)
    expect(witnessCheck(v).status).toBe('not_run')
  })

  it('does not count a stub, which was never registered', async () => {
    const reply = structuredClone(witnessed)
    for (const r of receiptsOf(reply)) Object.assign(r.witness, { is_stub: true, receipt_b64: '' })
    const v = await verifyHistoryReply(JSON.stringify(reply), readerList(WITNESS_KEY))
    expect(witnessCheck(v).status).toBe('not_run')
  })

  it('does not take a key from the reply: the reply cannot add a witness', async () => {
    const reply = structuredClone(witnessed) as Record<string, unknown>
    reply.witnesses = readerList(WITNESS_KEY).witnesses
    const v = await verifyHistoryReply(JSON.stringify(reply))
    expect(witnessCheck(v).status).toBe('not_run')
  })

  it('reads the reader’s list strictly', () => {
    expect(parseReaderWitnesses(readerList(WITNESS_KEY))).toEqual(readerList(WITNESS_KEY))
    expect(parseReaderWitnesses({ witnesses: [{ name: '', keys: [WITNESS_KEY] }] })).toBeNull()
    expect(parseReaderWitnesses({ witnesses: [{ name: 'w', keys: ['zz'] }] })).toBeNull()
    expect(parseReaderWitnesses({ witnesses: [{ name: 'w', keys: [WITNESS_KEY], extra: 1 }] })).toBeNull()
    expect(parseReaderWitnesses({ witnesses: [], extra: 1 })).toBeNull()
    expect(parseReaderWitnesses([])).toBeNull()
  })
})

