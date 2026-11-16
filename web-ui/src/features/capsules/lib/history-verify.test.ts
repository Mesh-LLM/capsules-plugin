import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
import { base64urlToBytes, verifyHistoryReply } from '@/features/capsules/lib/history-verify'

// A real reply from a corpus node (crates/evidence-plugin/tests/fixtures).
const fixture = JSON.parse(
  readFileSync(path.resolve(process.cwd(), '../crates/evidence-plugin/tests/fixtures/evidence_answers_5d2d102.json'), 'utf8')
) as Record<string, Record<string, unknown>>

const card = fixture.history_card
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
})
