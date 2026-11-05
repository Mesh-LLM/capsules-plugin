import { ed25519 } from '@noble/curves/ed25519'
import { describe, expect, it } from 'vitest'
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'
import {
  FIXTURE_PROVIDER_NODE,
  FIXTURE_REQUEST_DIGEST,
  FIXTURE_RESPONSE_DIGEST,
  fixtureHalfBody
} from '@/features/capsules/lib/pushed-half-fixtures'
import type { EvidenceVerification } from '@/features/capsules/api/evidenceRequestClient'
import type { PeerRecomputeState } from '@/features/capsules/lib/recompute-identity'
import {
  ASK_DID_NOT_GO_THROUGH,
  NOT_ON_MESH,
  askFailureSentence,
  askReplyNote,
  askTarget,
  recordRefusalWords,
  otherSideNodeId,
  rowAskControls,
  type RowAskInput,
  HOST_SERVED_NO_NONCE,
  judgeAskReply,
  producerSignatureVerifies,
  refusalSigningBody,
  settleRowAsk,
  type AskOutcome,
  type RowAsk,
  type AskJudges
} from './ask-for-record'
import { judgeRow } from './row-evidence'
import { formatExchangeTimestamp } from '@/features/capsules/lib/local-time'

const ASKED_AT = '2026-09-28T21:00:00Z'

/** The row's state after a run of asks, as the row derives it. */
function stateAfterAsks(row: PaneCRow, outcomes: AskOutcome[], local: unknown, fetched: PeerRecomputeState | null = null) {
  let ask: RowAsk | null = null
  for (const outcome of outcomes) ask = settleRowAsk(ask, outcome, local as never)
  return judgeRow(row, local as never, fetched, ask).state
}

function stateAfterAsk(row: PaneCRow, outcome: AskOutcome, local: unknown) {
  return stateAfterAsks(row, [outcome], local)
}
const NONCE = 'nonce-of-the-exchange'

function ourRequestedRecord(): Record<string, unknown> {
  const body = fixtureHalfBody({ capsuleId: 'ours-1' })
  const poc = (body.model_attestation as Record<string, Record<string, Record<string, unknown>>>).compute_attestation[
    'x-mesh-poc-v1'
  ]
  poc.role = 'requested'
  poc.client_nonce = NONCE
  return body
}

/** A row still waiting for their record: known peer, nothing received. */
function waitingRow(): PaneCRow {
  return {
    exchange_key: `digest:${FIXTURE_REQUEST_DIGEST}`,
    mine: { state: 'present', record: ourRequestedRecord() },
    theirs: { state: 'NOT_CHECKED', capsule_id: 'capsule-chatcmpl-1', peer_id: FIXTURE_PROVIDER_NODE }
  } as unknown as PaneCRow
}

const hex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')

/** The peer's own key, as this node was told it (`announced_key_id`). */
const PEER_SECRET = ed25519.utils.randomSecretKey()
const ANNOUNCED = hex(ed25519.getPublicKey(PEER_SECRET))
/** The digest of the request bytes the plugin sent. */
const SENT = 'f'.repeat(64)

function signedRefusal(reason: string, { secret = PEER_SECRET, requestDigest = SENT } = {}) {
  const refusal = { request_digest: requestDigest, reason, issued_at: '2026-09-28T21:00:05Z' }
  const sig = ed25519.sign(refusalSigningBody(refusal), secret)
  return { ...refusal, key_id: hex(ed25519.getPublicKey(secret)), sig: hex(sig) }
}

/** The tool's reply: the peer's answer, and what the plugin's verification
 *  found (by default, what a verified answer of that shape reads as). */
/** A reply whose verification reports `witnessed` witness receipts verified. */
function witnessedAnswer(body: Record<string, unknown>, witnessed: number) {
  return answer(body, ANNOUNCED, { state: 'artifact', records: artifactLeafIndices(body), witnessed })
}

/** A reply note that isn't witnessed never reads as verified (evidencebook#209). */
function expectNeverVerified(note: ReturnType<typeof askReplyNote>) {
  expect(note?.verified).toBe(false)
  expect(note?.text).not.toContain('✓')
  expect(note?.text).not.toMatch(/checks out|verified/i)
}

function answer(
  body: Record<string, unknown>,
  announcedKeyId: string | null = ANNOUNCED,
  verification?: EvidenceVerification,
  held: string[] = []
) {
  const found: EvidenceVerification =
    verification ??
    (typeof body.reason === 'string'
      ? { state: 'refusal', reason: body.reason }
      : { state: 'artifact', records: artifactLeafIndices(body) })
  return { kind: 'answer' as const, answer: body, verification: found, requestDigest: SENT, announcedKeyId, held }
}

/** An artifact answer carrying `records` (the interop profile's reply the
 *  plugin serves: the artifact's JSON text as unpadded base64url, each
 *  record's body hex-encoded). */
function artifact(records: Record<string, unknown>[]): Record<string, unknown> {
  const served = records.map((record, i) => ({
    leaf_index: i,
    digest: 'd'.repeat(64),
    body: hex(new TextEncoder().encode(JSON.stringify(record)))
  }))
  const text = JSON.stringify({ anchor: 'a'.repeat(64), evidence_stream: 'log', subject: { correlation: NONCE }, records: served })
  return {
    profile: 'evidence-interop/0',
    artifact_digest: 'b'.repeat(64),
    artifact: base64url(new TextEncoder().encode(text))
  }
}

function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function artifactLeafIndices(body: Record<string, unknown>): number[] {
  const text = atob(String(body.artifact).replace(/-/g, '+').replace(/_/g, '/'))
  const parsed = JSON.parse(text) as { records: { leaf_index: number }[] }
  return parsed.records.map((r) => r.leaf_index)
}

/** A COSE_Sign1 (EdDSA, attached payload) over `payload`, as the producer
 *  signs a record's `capsule_id`. */
function coseSign1(payload: Uint8Array, secret: Uint8Array): string {
  const protectedHeader = Uint8Array.of(0xa1, 0x01, 0x27)
  const sigStructure = Uint8Array.of(
    0x84,
    0x6a,
    ...new TextEncoder().encode('Signature1'),
    0x43,
    ...protectedHeader,
    0x40,
    0x58,
    payload.length,
    ...payload
  )
  const sig = ed25519.sign(sigStructure, secret)
  return hex(
    Uint8Array.of(0xd2, 0x84, 0x43, ...protectedHeader, 0xa0, 0x58, payload.length, ...payload, 0x58, 0x40, ...sig)
  )
}

function signedRecord(secret: Uint8Array): Record<string, unknown> {
  const id = new Uint8Array(32).fill(7)
  return { capsule_id: hex(id), key_id: hex(ed25519.getPublicKey(secret)), signature: coseSign1(id, secret) }
}

const trustingJudges: AskJudges = {
  recomputeIdMatch: async () => true,
  producerSignatureVerifies: () => true
}

describe('askTarget — a failed exchange', () => {
  it('has no record of theirs to ask for, even when the record names a peer and a nonce', () => {
    const record = ourRequestedRecord()
    const poc = (record.model_attestation as Record<string, Record<string, Record<string, unknown>>>).compute_attestation[
      'x-mesh-poc-v1'
    ]
    poc.outcome = 'failed'
    expect(askTarget(record)).toBeNull()
  })
})

describe('askTarget', () => {
  const DIGESTS = { request: FIXTURE_REQUEST_DIGEST, response: FIXTURE_RESPONSE_DIGEST }
  const poc = (record: Record<string, unknown>) =>
    (record.model_attestation as Record<string, Record<string, Record<string, unknown>>>).compute_attestation[
      'x-mesh-poc-v1'
    ]

  it('names the node that served our request, our nonce and both digests', () => {
    expect(askTarget(ourRequestedRecord())).toEqual({ peerId: FIXTURE_PROVIDER_NODE, nonce: NONCE, digests: DIGESTS })
  })

  it('never names the exchange by the placeholder nonce every host-served half shares', () => {
    const placeholder = ourRequestedRecord()
    poc(placeholder).client_nonce = HOST_SERVED_NO_NONCE
    expect(askTarget(placeholder)).toEqual({ peerId: FIXTURE_PROVIDER_NODE, nonce: null, digests: DIGESTS })
  })

  it('offers nothing without a full peer id, or without a nonce or both digests', () => {
    const noNonce = ourRequestedRecord()
    delete poc(noNonce).client_nonce
    expect(askTarget(noNonce)).toEqual({ peerId: FIXTURE_PROVIDER_NODE, nonce: null, digests: DIGESTS })
    delete (noNonce.effect as Record<string, unknown>).response_digest
    expect(askTarget(noNonce)).toBeNull()
    expect(askTarget(fixtureHalfBody({ servedBy: 'unknown' }))).toBeNull()
  })
})

describe('rowAskControls', () => {
  const target = { peerId: FIXTURE_PROVIDER_NODE, nonce: NONCE, digests: null }
  const input = (overrides: Partial<RowAskInput> = {}): RowAskInput => ({
    kind: 'open_not_given',
    target,
    peerId: FIXTURE_PROVIDER_NODE,
    canAsk: true,
    roleTag: 'ASKED',
    servedForPay: false,
    recordAsk: null,
    historyAsk: null,
    ...overrides
  })

  it('offers both asks at once on a row whose record has not arrived: no timeout', () => {
    for (const kind of ['open_not_given', 'open_not_held', 'open_not_asked'] as const) {
      expect(rowAskControls(input({ kind }))).toEqual({
        record: { label: 'Ask for their record', disabledReason: null },
        history: { label: 'Ask for their history', disabledReason: null }
      })
    }
  })

  it('offers asking again after an ask', () => {
    for (const kind of ['open_asked'] as const) {
      expect(rowAskControls(input({ kind })).record).toEqual({ label: 'Ask again for their record', disabledReason: null })
    }
  })

  it('keeps the record ask on a settled row, disabled with why; the history ask stays live', () => {
    expect(rowAskControls(input({ kind: 'closed' })).record.disabledReason).toBe(
      'Their record is already here and checks out.'
    )
    expect(rowAskControls(input({ kind: 'contradicted' })).record.disabledReason).toMatch(/Compare shows where/)
    expect(rowAskControls(input({ kind: 'closed' })).history.disabledReason).toBeNull()
  })

  it('says why when there is no one to ask, by which truth holds', () => {
    const asked = rowAskControls(input({ target: null, peerId: null }))
    expect(asked.record.disabledReason).toBe('Your record doesn’t name the node that answered, so there is no one to ask.')
    expect(asked.history.disabledReason).toBe(asked.record.disabledReason)
    expect(rowAskControls(input({ target: null, peerId: null, roleTag: 'SERVED' })).record.disabledReason).toBe(
      'No other node took part in this exchange, so there is no one to ask.'
    )
    expect(
      rowAskControls(input({ target: null, peerId: null, roleTag: 'SERVED', servedForPay: true })).history.disabledReason
    ).toBe('Your record doesn’t name the node that paid, so there is no one to ask.')
    // The row knows a node took part (Pane B) though our record doesn't name
    // it: never "No other node took part".
    expect(
      rowAskControls(input({ target: null, peerId: null, roleTag: 'SERVED', otherSideKnown: true })).record.disabledReason
    ).toBe('Your record doesn’t name the node that asked, so there is no one to ask.')
    expect(
      rowAskControls(input({ target: null, peerId: null, roleTag: 'ASKED', otherSideKnown: true })).record.disabledReason
    ).toBe('Your record doesn’t name the node that answered, so there is no one to ask.')
    // A named node, but nothing to name the exchange by: only the history ask can go.
    const unnamed = rowAskControls(input({ target: null }))
    expect(unnamed.record.disabledReason).toMatch(/doesn’t name this exchange/)
    expect(unnamed.history.disabledReason).toBeNull()
  })

  it('is disabled on a saved sample, and while an ask is in flight', () => {
    const sample = rowAskControls(input({ canAsk: false }))
    expect(sample.record.disabledReason).toBe('Not available on sample data.')
    expect(sample.history.disabledReason).toBe('Not available on sample data.')
    const asking = rowAskControls(
      input({ recordAsk: { kind: 'asking', at: ASKED_AT }, historyAsk: { kind: 'asking' } })
    )
    expect(asking.record).toEqual({ label: 'Asking…', disabledReason: 'Waiting for their reply.' })
    expect(asking.history).toEqual({ label: 'Asking…', disabledReason: 'Waiting for their reply.' })
  })

  it('names the other side from our record, whichever role we had', () => {
    expect(otherSideNodeId(ourRequestedRecord())).toBe(FIXTURE_PROVIDER_NODE)
    expect(otherSideNodeId(fixtureHalfBody({ servedBy: 'unknown' }))).toBeNull()
    const asker = 'ab'.repeat(32)
    const served = (provenance: Record<string, unknown>) => ({
      model_attestation: {
        compute_attestation: { 'x-mesh-poc-v1': { role: 'served', serving_provenance: provenance } }
      }
    })
    // The plugin seals the node that asked as `requesting_party`.
    expect(otherSideNodeId(served({ requesting_party: asker, served_by_node_id: 'cd'.repeat(32) }))).toBe(asker)
    // A record carrying the host's raw field still names it.
    expect(otherSideNodeId(served({ requested_by_node_id: asker }))).toBe(asker)
    expect(otherSideNodeId(served({ requesting_party: 'unknown' }))).toBeNull()
  })
})

describe('judgeAskReply', () => {
  it('reads a signed no_such_subject as their signed statement that they have no record', async () => {
    const outcome = await judgeAskReply(answer(signedRefusal('no_such_subject')), null, ASKED_AT)
    expect(outcome).toEqual({ kind: 'no_record', at: '2026-09-28T21:00:05Z' })
    expect(stateAfterAsk(waitingRow(), outcome, null)).toEqual({ kind: 'open_absent', date: '2026-09-28T21:00:05Z' })
  })

  it('reads any other signed reason as a signed decline', async () => {
    const outcome = await judgeAskReply(answer(signedRefusal('policy_declined')), null, ASKED_AT)
    expect(outcome).toEqual({ kind: 'refused', at: '2026-09-28T21:00:05Z', reason: 'policy_declined' })
    expect(stateAfterAsk(waitingRow(), outcome, null).kind).toBe('open_refused')
  })

  it('reads a signed coverage lag as not yet provable: the row stays asked and can ask again', async () => {
    const outcome = await judgeAskReply(answer(signedRefusal('coverage_unsatisfiable')), null, ASKED_AT)
    expect(outcome.kind).toBe('no_reply')
    expect(stateAfterAsk(waitingRow(), outcome, null)).toEqual({ kind: 'open_asked', date: ASKED_AT })
  })

  it('never takes a refusal whose signature does not verify', async () => {
    const forged = { ...signedRefusal('no_such_subject'), reason: 'policy_declined' }
    const outcome = await judgeAskReply(answer(forged), null, ASKED_AT)
    expect(outcome.kind).toBe('no_reply')
    expect(stateAfterAsk(waitingRow(), outcome, null)).toEqual({ kind: 'open_asked', date: ASKED_AT })
  })

  // Adversarial read: a refusal must be theirs, and about this ask.
  it('never takes a refusal signed with a throwaway key instead of their announced one', async () => {
    const throwaway = signedRefusal('no_such_subject', { secret: ed25519.utils.randomSecretKey() })
    const outcome = await judgeAskReply(answer(throwaway), null, ASKED_AT)
    expect(outcome).toMatchObject({ kind: 'no_reply', detail: 'their reply is not signed with the key this node has for them' })
    expect(stateAfterAsk(waitingRow(), outcome, null).kind).toBe('open_asked')
  })

  it('never takes a refusal replayed from a different request', async () => {
    const replayed = signedRefusal('no_such_subject', { requestDigest: 'e'.repeat(64) })
    const outcome = await judgeAskReply(answer(replayed), null, ASKED_AT)
    expect(outcome).toMatchObject({ kind: 'no_reply', detail: 'their reply answers a different request' })
  })

  it('takes nothing as their refusal when this node has no announced key for them', async () => {
    const outcome = await judgeAskReply(answer(signedRefusal('no_such_subject'), null), null, ASKED_AT)
    expect(outcome.kind).toBe('no_reply')
  })

  it('takes nothing the plugin could not verify, and says why', async () => {
    const theirs = { ...fixtureHalfBody({ capsuleId: 'theirs-1' }), signature: 'aa', key_id: 'bb' }
    const outcome = await judgeAskReply(
      answer(artifact([theirs]), ANNOUNCED, { state: 'not_evidence', why: 'a proof does not verify against the anchor' }),
      FIXTURE_REQUEST_DIGEST,
      ASKED_AT,
      trustingJudges
    )
    expect(outcome).toEqual({
      kind: 'no_reply',
      at: ASKED_AT,
      detail: 'their reply did not verify: a proof does not verify against the anchor'
    })
    expect(stateAfterAsk(waitingRow(), outcome, ourRequestedRecord() as never).kind).toBe('open_asked')
    expect(askReplyNote(outcome)).toEqual({
      verified: false,
      text: 'Their reply is not verified: their reply did not verify: a proof does not verify against the anchor'
    })
  })

  it('takes nothing when the plugin had no announced key to check the reply under', async () => {
    const outcome = await judgeAskReply(
      answer(signedRefusal('no_such_subject'), null, { state: 'no_announced_key' }),
      null,
      ASKED_AT
    )
    expect(outcome).toMatchObject({ kind: 'no_reply' })
    expect(askReplyNote(outcome)?.verified).toBe(false)
  })

  it('never takes a refusal whose reason differs from the one the plugin verified', async () => {
    const outcome = await judgeAskReply(
      answer(signedRefusal('no_such_subject'), ANNOUNCED, { state: 'refusal', reason: 'policy_declined' }),
      null,
      ASKED_AT
    )
    expect(outcome.kind).toBe('no_reply')
  })

  it('keeps the row asked, no reply yet, when the other side could not be reached', async () => {
    const outcome = await judgeAskReply({ kind: 'no_answer', message: 'peer unreachable' }, null, ASKED_AT)
    expect(stateAfterAsk(waitingRow(), outcome, null)).toEqual({ kind: 'open_asked', date: ASKED_AT })
  })

  it('says a tool error in plain words, never the raw message', async () => {
    expect(askFailureSentence('could not reach peer: connection lost')).toBe(NOT_ON_MESH)
    expect(askFailureSentence('peer is not routable on this mesh')).toBe(NOT_ON_MESH)
    expect(askFailureSentence('{"code":-32603,"message":"peer returned malformed response"}')).toBe(ASK_DID_NOT_GO_THROUGH)
    const outcome = await judgeAskReply({ kind: 'no_answer', message: 'could not reach peer: gone' }, null, ASKED_AT)
    expect(outcome).toEqual({ kind: 'no_reply', at: ASKED_AT, detail: NOT_ON_MESH, plain: true })
    expect(askReplyNote(outcome)).toEqual({ verified: false, text: 'That node isn’t on the mesh now, so it can’t be asked.' })
  })

  it('gives a declined record ask its reason in plain words, and never echoes an unknown token', async () => {
    const refusal = await judgeAskReply(answer(signedRefusal('not_authorized')), null, ASKED_AT)
    // "Signed refusal, {time}: {reason}." -- the decline said once, with its time.
    expect(askReplyNote(refusal)?.text).toBe(
      `Signed refusal, ${formatExchangeTimestamp(refusal.at)}: their sharing settings don’t let them send it to this node. Their reply is verified: signed with the key this node has for them, for this request.`
    )
    expect(askReplyNote(refusal)?.text.match(/declined/g)).toBeNull()
    for (const reason of ['policy_declined', 'deadline_unmet', 'request_malformed', 'retention_expired', 'derivation_unsupported']) {
      expect(recordRefusalWords(reason)).not.toContain('_')
    }
    expect(recordRefusalWords('made_up_token')).toBe('for a reason this page can’t name')
  })

  it('marks a record saved only when the tool held its id', async () => {
    const theirs = { ...fixtureHalfBody({ capsuleId: 'theirs-1' }), signature: 'aa', key_id: 'bb' }
    const judge = (held: string[]) =>
      judgeAskReply(answer(artifact([theirs]), ANNOUNCED, undefined, held), FIXTURE_REQUEST_DIGEST, ASKED_AT, trustingJudges)
    expect(await judge(['theirs-1'])).toMatchObject({ kind: 'record', saved: true })
    expect(await judge([])).toMatchObject({ kind: 'record', saved: false })
    expect(await judge(['someone-else'])).toMatchObject({ kind: 'record', saved: false })
  })

  it('says a verified reply is verified', async () => {
    const refusal = await judgeAskReply(answer(signedRefusal('no_such_subject')), null, ASKED_AT)
    expect(askReplyNote(refusal)?.verified).toBe(true)
    const theirs = { ...fixtureHalfBody({ capsuleId: 'theirs-1' }), signature: 'aa', key_id: 'bb' }
    const record = await judgeAskReply(witnessedAnswer(artifact([theirs]), 1), FIXTURE_REQUEST_DIGEST, ASKED_AT, trustingJudges)
    expect(askReplyNote(record)).toMatchObject({ verified: true })
    expect(askReplyNote({ kind: 'asking', at: ASKED_AT })).toBeNull()
  })

  it('a record a witness this node trusts vouches for is verified, and says the witness holds their checkpoint', async () => {
    const theirs = { ...fixtureHalfBody({ capsuleId: 'theirs-1' }), signature: 'aa', key_id: 'bb' }
    const record = await judgeAskReply(witnessedAnswer(artifact([theirs]), 2), FIXTURE_REQUEST_DIGEST, ASKED_AT, trustingJudges)
    expect(record).toMatchObject({ kind: 'record', witness: 'witnessed' })
    expect(askReplyNote(record)).toEqual({
      verified: true,
      witness: 'witnessed',
      text: 'Their reply is verified: the record is in their log, under a checkpoint signed with the key this node has for them, and a witness this node trusts holds their checkpoint'
    })
  })

  it('a record no configured witness vouches for checks against their own signatures only, never "verified"', async () => {
    const theirs = { ...fixtureHalfBody({ capsuleId: 'theirs-1' }), signature: 'aa', key_id: 'bb' }
    const record = await judgeAskReply(witnessedAnswer(artifact([theirs]), 0), FIXTURE_REQUEST_DIGEST, ASKED_AT, trustingJudges)
    expect(record).toMatchObject({ kind: 'record', witness: 'unwitnessed' })
    const note = askReplyNote(record)
    expect(note).toEqual({
      verified: false,
      witness: 'unwitnessed',
      text: 'Their record checks against their own signatures only: it is in their log, under a checkpoint signed with the key this node has for them, but no witness this node trusts has vouched for that log, so it could be a private copy'
    })
    expectNeverVerified(note)
    // The row may still close: the witness clause is on the reply line only.
    expect(stateAfterAsk(waitingRow(), record, ourRequestedRecord() as never).kind).toBe(
      stateAfterAsk(waitingRow(), { ...record, witness: 'witnessed' } as never, ourRequestedRecord() as never).kind
    )
  })

  it('a record checked with no witness configured says there was none to check it against', async () => {
    const theirs = { ...fixtureHalfBody({ capsuleId: 'theirs-1' }), signature: 'aa', key_id: 'bb' }
    const record = await judgeAskReply(answer(artifact([theirs])), FIXTURE_REQUEST_DIGEST, ASKED_AT, trustingJudges)
    expect(record).toMatchObject({ kind: 'record', witness: 'no_witness' })
    const note = askReplyNote(record)
    expect(note).toEqual({
      verified: false,
      witness: 'no_witness',
      text: 'Their record checks against their own signatures only: it is in their log, under a checkpoint signed with the key this node has for them. This node has no witness configured to check it against, so it could be a private copy'
    })
    expectNeverVerified(note)
    // An outcome that carries no standing reads the same, never as witnessed.
    const { witness: _dropped, ...unstated } = record as Extract<typeof record, { kind: 'record' }>
    expect(askReplyNote(unstated)).toEqual(note)
  })

  it('says a record is verified only when its id recomputes and its signature holds', async () => {
    const theirs = { ...fixtureHalfBody({ capsuleId: 'theirs-1' }), signature: 'aa', key_id: 'bb' }
    const judged = (judges: AskJudges) =>
      judgeAskReply(witnessedAnswer(artifact([theirs]), 1), FIXTURE_REQUEST_DIGEST, ASKED_AT, judges)
    expect(askReplyNote(await judged(trustingJudges))?.verified).toBe(true)
    expect(askReplyNote(await judged({ ...trustingJudges, producerSignatureVerifies: () => false }))).toEqual({
      verified: false,
      text: 'Their record is in their log, but it is not verified: it is not signed with the key this node has for them'
    })
    expect(askReplyNote(await judged({ ...trustingJudges, recomputeIdMatch: async () => false }))).toEqual({
      verified: false,
      text: 'Their record is in their log, but it is not verified: its id doesn’t match its contents'
    })
    expect(askReplyNote(await judged({ ...trustingJudges, recomputeIdMatch: async () => null }))?.verified).toBe(false)
  })

  it('reads the artifact as the profile carries it, base64url, never as raw JSON text', async () => {
    const theirs = { ...fixtureHalfBody({ capsuleId: 'theirs-1' }), signature: 'aa', key_id: 'bb' }
    const reply = artifact([theirs])
    const record = await judgeAskReply(answer(reply), FIXTURE_REQUEST_DIGEST, ASKED_AT, trustingJudges)
    expect(record.kind).toBe('record')
    const asText = { ...reply, artifact: atob(String(reply.artifact).replace(/-/g, '+').replace(/_/g, '/')) }
    const outcome = await judgeAskReply(
      answer(asText, ANNOUNCED, { state: 'artifact', records: [0] }),
      FIXTURE_REQUEST_DIGEST,
      ASKED_AT,
      trustingJudges
    )
    expect(outcome).toMatchObject({ kind: 'no_reply', detail: 'their reply carried no record' })
  })

  it('reads only the records the plugin proved', async () => {
    const theirs = { ...fixtureHalfBody({ capsuleId: 'theirs-1' }), signature: 'aa', key_id: 'bb' }
    const outcome = await judgeAskReply(
      answer(artifact([theirs]), ANNOUNCED, { state: 'artifact', records: [] }),
      FIXTURE_REQUEST_DIGEST,
      ASKED_AT,
      trustingJudges
    )
    expect(outcome).toMatchObject({ kind: 'no_reply', detail: 'their reply carried no record' })
  })

  // Asked by the exchange's digests, a node can answer with more than one
  // record carrying them: the half it served and, say, a half it requested.
  function theirHalf(capsuleId: string, role: 'served' | 'requested'): Record<string, unknown> {
    const body = fixtureHalfBody({ capsuleId })
    ;(body.model_attestation as Record<string, Record<string, Record<string, unknown>>>).compute_attestation[
      'x-mesh-poc-v1'
    ].role = role
    return { ...body, signature: 'aa', key_id: 'bb' }
  }

  it('prefers the half they served among records with our digests', async () => {
    const served = theirHalf('theirs-served', 'served')
    const requested = theirHalf('theirs-requested', 'requested')
    const outcome = await judgeAskReply(
      answer(artifact([requested, served])),
      FIXTURE_REQUEST_DIGEST,
      ASKED_AT,
      trustingJudges
    )
    expect(outcome).toMatchObject({ kind: 'record', evidence: { peerRecord: { capsule_id: 'theirs-served' } } })
  })

  it('never picks one of several records that could be theirs by order: the reply is ambiguous', async () => {
    const one = theirHalf('theirs-1', 'served')
    const two = theirHalf('theirs-2', 'served')
    const outcome = await judgeAskReply(answer(artifact([one, two])), FIXTURE_REQUEST_DIGEST, ASKED_AT, trustingJudges)
    expect(outcome).toEqual({ kind: 'ambiguous', at: ASKED_AT, count: 2 })
    expect(askReplyNote(outcome)).toEqual({
      verified: false,
      text: 'Their reply carried 2 records that could be theirs for this exchange; none is shown as theirs'
    })
    expect(stateAfterAsk(waitingRow(), outcome, null)).toEqual({ kind: 'open_asked', date: ASKED_AT })
  })

  it('closes the row through the gate when their record verifies and cites our half', async () => {
    const theirs = { ...fixtureHalfBody({ capsuleId: 'theirs-1' }), signature: 'aa', key_id: 'bb' }
    const outcome = await judgeAskReply(
      answer(artifact([theirs])),
      FIXTURE_REQUEST_DIGEST,
      ASKED_AT,
      trustingJudges
    )
    expect(outcome.kind).toBe('record')
    const ours = ourRequestedRecord()
    expect(stateAfterAsk(waitingRow(), outcome, ours as never).kind).toBe('closed')
  })

  it('closes a row the pane still shows with no other side once their verified record arrives (never "not received")', async () => {
    const theirs = { ...fixtureHalfBody({ capsuleId: 'theirs-1' }), signature: 'aa', key_id: 'bb' }
    const outcome = await judgeAskReply(answer(artifact([theirs])), FIXTURE_REQUEST_DIGEST, ASKED_AT, trustingJudges)
    const paneAbsent = { ...waitingRow(), theirs: { state: 'absent', capsule_id: null } } as unknown as PaneCRow
    expect(stateAfterAsk(paneAbsent, outcome, ourRequestedRecord() as never).kind).toBe('closed')
    // Our record from the pane's own copy when none was fetched.
    expect(stateAfterAsk(paneAbsent, outcome, null).kind).toBe('closed')
  })

  it('never closes the row on a record whose signature does not verify', async () => {
    const theirs = { ...fixtureHalfBody({ capsuleId: 'theirs-1' }), signature: 'aa', key_id: 'bb' }
    const outcome = await judgeAskReply(
      answer(artifact([theirs])),
      FIXTURE_REQUEST_DIGEST,
      ASKED_AT,
      { ...trustingJudges, producerSignatureVerifies: () => false }
    )
    expect(stateAfterAsk(waitingRow(), outcome, ourRequestedRecord() as never).kind).not.toBe('closed')
  })

  it('reads their record with a different answer as a disagreement', async () => {
    const theirs = {
      ...fixtureHalfBody({ capsuleId: 'theirs-1', responseDigest: 'e'.repeat(64) }),
      signature: 'aa',
      key_id: 'bb'
    }
    const outcome = await judgeAskReply(
      answer(artifact([theirs])),
      FIXTURE_REQUEST_DIGEST,
      ASKED_AT,
      trustingJudges
    )
    expect(stateAfterAsk(waitingRow(), outcome, ourRequestedRecord() as never).kind).toBe('contradicted')
  })
})

describe('judgeAskReply: their record under the announced key', () => {
  const realSignature: AskJudges = { recomputeIdMatch: async () => true, producerSignatureVerifies }

  it('counts a fetched record as signed only under the key they announced', async () => {
    for (const [secret, expected] of [
      [PEER_SECRET, true],
      [ed25519.utils.randomSecretKey(), false]
    ] as const) {
      const outcome = await judgeAskReply(
        answer(artifact([signedRecord(secret)])),
        null,
        ASKED_AT,
        realSignature
      )
      expect(outcome.kind === 'record' && outcome.evidence.status === 'found' && outcome.evidence.signatureOk).toBe(
        expected
      )
    }
  })
})

describe('producerSignatureVerifies', () => {
  it('holds for a record signed with their announced key', () => {
    expect(producerSignatureVerifies(signedRecord(PEER_SECRET), ANNOUNCED)).toBe(true)
  })

  it('fails for a record validly signed with any other key, or with no announced key', () => {
    const throwaway = signedRecord(ed25519.utils.randomSecretKey())
    expect(producerSignatureVerifies(throwaway, ANNOUNCED)).toBe(false)
    expect(producerSignatureVerifies(signedRecord(PEER_SECRET), null)).toBe(false)
  })

  it('fails when the envelope does not sign the record’s own id', () => {
    const record = signedRecord(PEER_SECRET)
    expect(producerSignatureVerifies({ ...record, capsule_id: '08'.repeat(32) }, ANNOUNCED)).toBe(false)
  })
})
