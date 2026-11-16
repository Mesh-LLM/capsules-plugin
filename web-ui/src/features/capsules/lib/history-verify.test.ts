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

  it('names the field when a checkpoint is refused for the format of its issued_at, not for its signature', async () => {
    const artifact = artifactOf(card) as { history: { checkpoint: string }[] }
    // The T of the first checkpoint's issued_at becomes a space: the same length, so still valid CBOR, but no longer RFC 3339.
    const bytes = Buffer.from(artifact.history[0].checkpoint, 'hex')
    const at = bytes.toString('latin1').search(/\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d/)
    expect(at).toBeGreaterThan(0)
    bytes[at + 10] = 0x20
    artifact.history[0].checkpoint = bytes.toString('hex')
    const v = await verifyHistoryReply(JSON.stringify({ ...card, ...(await encodeArtifact(artifact)) }))
    expect(v.verified).toBe(false)
    expect(failed(v)).toBe('checkpoints')
    const detail = v.checks.find((c) => c.status === 'fail')?.detail
    expect(detail).toBe('Checkpoint 1: `issued_at` is not in the expected format (a format rejection, not a failed signature).')
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
