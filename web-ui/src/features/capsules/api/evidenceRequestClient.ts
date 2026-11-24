// Ask the other side of an exchange for its record: this plugin's
// `mesh_evidence_request` tool (`tools/mesh_evidence_request`) sends one
// evidence request (draft-mih-agent-evidence-request-00) to that node over
// the mesh. The tool verifies what comes back before handing it over
// (`evidence_answer::verify_response`, under the key the operator announced
// for that node in `CAPSULES_PEER_KEYS`) and answers
// `{answer, request_digest, verification}`: the peer's reply unchanged, the
// digest of the request bytes it actually sent, and what the reply proved.
// This client carries that; `ask-for-record.ts` judges it.
//
// Ported from the fork console, which reached the same tool through a host
// route (`POST /api/evidence-requests`) that also looked up the key.
import { getPluginJson, pluginHost } from '@/plugin-host/host'

export const EVIDENCE_REQUEST_ROUTE = 'tools/mesh_evidence_request'
export const peerKeyRoute = (peerId: string) => `http/peer-key?peer=${encodeURIComponent(peerId)}`

/** The interop profile every request follows: a requester following it
 *  MUST name it (agent-action-capsule interop-profile-v0 §3.3 step 2, P-2),
 *  and the tool's verification holds the reply's envelope to it. */
export const INTEROP_PROFILE = 'evidence-interop/0'

/** What the tool's verification found (`evidence_answer::verify_response`):
 *  a refusal signed with the announced key for our request; an artifact that
 *  verifies (the served records, by leaf index); a reply that proves nothing;
 *  or no announced key to check it under. `unknown` for anything else.
 *  An artifact's `witnessed` is how many of its witness receipts verified,
 *  under a witness key the operator configured, for the answer's anchor
 *  checkpoint (`anchorWitnessed`); it is absent when no witness key is
 *  configured, so there was nothing to check them against. */
export type EvidenceVerification =
  | { state: 'refusal'; reason: string }
  | { state: 'artifact'; records: number[]; checkpoints?: number; witnessed?: number }
  | { state: 'not_evidence'; why: string }
  | { state: 'no_announced_key' }
  | { state: 'unknown' }

/** An answer comes with what it must be judged against: the tool's
 *  verification; the digest of the request bytes the tool sent, which a
 *  refusal must name; and the key this node was told the peer signs with
 *  (`null` when none is announced), which the record's own signature is
 *  checked under. */
export type EvidenceAskReply =
  | {
      kind: 'answer'
      answer: unknown
      verification: EvidenceVerification
      requestDigest: string
      announcedKeyId: string | null
      /** The card form a history ask was made in (`askForHistory`): a
       *  `history_card/2` lists a sample of the log, not all of it. */
      derivation?: string
      /** The `capsule_id`s of their records the plugin saved on this node from
       *  this reply (the tool's `held`): `[]` when it saved none (a store
       *  failure, a receiver refusal, or no single matching record), and
       *  when the tool didn't say. */
      held: string[]
    }
  | { kind: 'no_answer'; message: string }

/** The -00 request for the records carrying one client nonce: a correlation
 *  subject, under the freshest checkpoint the peer holds. */
export function askByNonceRequest(nonce: string): Record<string, unknown> {
  return { profile: INTEROP_PROFILE, coverage: { min_freshness: 1 }, subject: { correlation: nonce } }
}

/** The correlation identifier that names an exchange by both of its digests
 *  (`evidence_log::exchange_binding`): a record matches only when its
 *  `effect` carries exactly these two. */
export function exchangeBinding(requestDigest: string, responseDigest: string): string {
  return `exchange-digests:${requestDigest}:${responseDigest}`
}

/** The -00 request for the records of the exchange with these two digests. */
export function askByDigestsRequest(digests: ExchangeDigests): Record<string, unknown> {
  return {
    profile: INTEROP_PROFILE,
    coverage: { min_freshness: 1 },
    subject: { correlation: exchangeBinding(digests.request, digests.response) }
  }
}

/** The card forms asked of a peer, newest first (the order `admission::base`
 *  asks in, `CARD_FORM` then `OLDER_CARD_FORM`): `history_card/2` samples the log
 *  (ER -03 §8.1.2), and a build before it was answered serves only
 *  `history_card/1`, the whole list (-00 registry, `evidence_artifact::build`). */
export const HISTORY_CARD_DERIVATIONS = ['history_card/2', 'history_card/1'] as const

/** The -00 request for the peer's history card, in `derivation`, over its
 *  whole log, under the freshest checkpoint it holds. */
export function askForHistoryRequest(derivation: string = HISTORY_CARD_DERIVATIONS[0]): Record<string, unknown> {
  return {
    profile: INTEROP_PROFILE,
    coverage: { min_freshness: 1 },
    subject: { full_history: null },
    derivation
  }
}

export type ExchangeDigests = { request: string; response: string }

/** How to name the exchange to the other side: the client nonce our record
 *  carries, and the exchange's two digests. Either may be unknown. */
export type AskSubject = { nonce: string | null; digests: ExchangeDigests | null }

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : null
}

/** How many of the tool's receipts verified for the anchor checkpoint. The
 *  tool's own `witnessed` counts a receipt on any checkpoint the answer
 *  carries, but a receipt on an older checkpoint leaves every later one, the
 *  anchor included, possibly a private extension (evidencebook#209). So only
 *  `receipts` entries that verified and name the anchor count; with no
 *  readable anchor or receipts, none do. */
export function anchorWitnessed(v: Record<string, unknown>): number {
  const anchor = typeof v.anchor === 'string' ? v.anchor : null
  if (anchor === null || !Array.isArray(v.receipts)) return 0
  return v.receipts.filter((r) => {
    const entry = record(r)
    return entry?.status === 'verified' && entry.checkpoint === anchor
  }).length
}

function parseVerification(value: unknown): EvidenceVerification {
  const v = record(value)
  switch (v?.state) {
    case 'refusal':
      return typeof v.reason === 'string' ? { state: 'refusal', reason: v.reason } : { state: 'unknown' }
    case 'artifact':
      return Array.isArray(v.records) && v.records.every((i) => Number.isInteger(i))
        ? {
            state: 'artifact',
            records: v.records as number[],
            ...(Number.isInteger(v.checkpoints) ? { checkpoints: v.checkpoints as number } : {}),
            ...(Number.isInteger(v.witnessed) && (v.witnessed as number) >= 0 ? { witnessed: anchorWitnessed(v) } : {})
          }
        : { state: 'unknown' }
    case 'not_evidence':
      return { state: 'not_evidence', why: typeof v.why === 'string' ? v.why : 'it did not verify' }
    case 'no_announced_key':
      return { state: 'no_announced_key' }
    default:
      return { state: 'unknown' }
  }
}

/** The tool's `held`: only a list of non-empty strings counts; anything
 *  else is "saved nothing". */
function heldIds(value: unknown): string[] {
  return Array.isArray(value) && value.every((id) => typeof id === 'string' && id.length > 0) ? (value as string[]) : []
}

/** The key this node was told `peerId` signs with, or `null` when none is
 *  announced or the route can't say: an unknown key is never a guess. The
 *  plugin's `peer-key` route reads the host's announced keys (on a host with
 *  `plugin_keys.v1`) and the operator's `CAPSULES_PEER_KEYS`; off such a
 *  host it answers from the operator's map alone, or `null`. */
export async function announcedKeyFor(peerId: string): Promise<string | null> {
  try {
    const body = await getPluginJson<{ announced_key_id?: unknown }>(peerKeyRoute(peerId))
    return typeof body.announced_key_id === 'string' ? body.announced_key_id.toLowerCase() : null
  } catch {
    return null
  }
}

/** Ask by the client nonce first; when the other side answers, signed, that
 *  it holds no record of that nonce, ask again by the exchange's two
 *  digests. A node serving an exchange it was not handed a nonce for seals
 *  its half with a placeholder nonce, so only the digests find that half.
 *  With no nonce, ask by the digests alone. The reply returned is the last
 *  one, judged on its own like any other. */
export async function askForRecord(peerId: string, subject: AskSubject): Promise<EvidenceAskReply> {
  const { nonce, digests } = subject
  if (nonce === null) {
    return digests ? ask(peerId, askByDigestsRequest(digests)) : { kind: 'no_answer', message: 'nothing names the exchange' }
  }
  const byNonce = await ask(peerId, askByNonceRequest(nonce))
  const noRecord =
    byNonce.kind === 'answer' &&
    byNonce.verification.state === 'refusal' &&
    byNonce.verification.reason === 'no_such_subject'
  return noRecord && digests ? ask(peerId, askByDigestsRequest(digests)) : byNonce
}

/** Whether a refusal is what a build gives a card form it does not serve:
 *  `derivation_unsupported` to a counterparty, or the `policy_declined` its
 *  gate gives everyone else for any derivation it does not offer strangers
 *  (`admission::base::ask_older_card`). Any other answer is judged as it is. */
function refusesThisForm(reply: EvidenceAskReply): boolean {
  return (
    reply.kind === 'answer' &&
    reply.verification.state === 'refusal' &&
    (reply.verification.reason === 'derivation_unsupported' || reply.verification.reason === 'policy_declined')
  )
}

/** Ask `peerId` for its history card: `history_card/2`, then `history_card/1`
 *  once if the peer refuses that form as an older build does. The reply is
 *  judged in `ask-for-history.ts`; the last one asked is the one returned. */
export async function askForHistory(peerId: string): Promise<EvidenceAskReply> {
  const [newer, older] = HISTORY_CARD_DERIVATIONS
  const first = await ask(peerId, askForHistoryRequest(newer))
  const [reply, form] = refusesThisForm(first) ? [await ask(peerId, askForHistoryRequest(older)), older] : [first, newer]
  return reply.kind === 'answer' ? { ...reply, derivation: form } : reply
}

async function ask(peerId: string, request: Record<string, unknown>): Promise<EvidenceAskReply> {
  let response: Response
  try {
    // No `verify` member: the tool verifies unless told not to.
    response = await pluginHost().network.fetchPlugin(EVIDENCE_REQUEST_ROUTE, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ peer_id: peerId, request })
    })
  } catch (error) {
    return { kind: 'no_answer', message: error instanceof Error ? error.message : 'network error' }
  }
  if (!response.ok) {
    const text = await response.text().catch(() => '')
    return { kind: 'no_answer', message: text || `HTTP ${response.status}` }
  }
  let body: unknown
  try {
    body = await response.json()
  } catch {
    return { kind: 'no_answer', message: 'the reply was not JSON' }
  }
  const reply = record(body)
  const answer = record(reply?.answer)
  const requestDigest = typeof reply?.request_digest === 'string' ? reply.request_digest.toLowerCase() : null
  if (!answer || !requestDigest || !/^[0-9a-f]{64}$/.test(requestDigest))
    return { kind: 'no_answer', message: 'the reply carried no answer' }
  return {
    kind: 'answer',
    answer,
    verification: parseVerification(reply?.verification),
    requestDigest,
    announcedKeyId: await announcedKeyFor(peerId),
    held: heldIds(reply?.held)
  }
}
