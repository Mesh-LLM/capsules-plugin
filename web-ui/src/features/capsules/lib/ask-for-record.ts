// "Ask for their record" (UX §3): a row whose other side's record hasn't
// arrived can ask that node for it, as soon as our record names that node. The plugin sends one
// evidence request over the mesh and verifies the reply before handing it
// over (`api/evidenceRequestClient.ts`); this module judges what came back,
// the same way the row judges a record that was pushed: nothing here is
// trusted because it arrived.
//
//   - only a reply the plugin verified counts (`verification`): a refusal
//     signed with the key this node was told the peer signs with, naming OUR
//     request, or an artifact whose records are proven in the peer's log
//     under a checkpoint that key signed. Anything else -- no announced key,
//     a reply that proves nothing -- leaves the row "asked, no reply yet",
//     and the row says why (`askReplyNote`);
//   - a refusal is also checked here, in the browser, under the announced
//     key and the request digest the plugin sent. `no_such_subject` is their
//     signed "I have no record of this"; `coverage_unsatisfiable` means they
//     hold it but no checkpoint covers it yet, so the row stays asked and can
//     ask again; any other reason is a signed decline;
//   - a record is judged by THE row gate (`recordVerdict`): only a verified
//     one (its id matches its contents, its signature holds under the key
//     this node has for them) gives a verdict. How it weighs against the
//     other sources of their record is `row-evidence.ts`.
import { ed25519 } from '@noble/curves/ed25519'
import type { CapsuleRecord } from '@/features/capsules/api/types'
import type { AskSubject, EvidenceAskReply } from '@/features/capsules/api/evidenceRequestClient'
import { verifyCoseSign1 } from '@/features/capsules/lib/cose'
import {
  fullTimeInstant,
  isVerifiedRecord,
  recordVerdict,
  type RightCellStateKind
} from '@/features/capsules/lib/exchange-row-state'
import { recomputeIdMatch, type PeerRecomputeState } from '@/features/capsules/lib/recompute-identity'
import { formatExchangeTimestamp } from '@/features/capsules/lib/local-time'
import { SAMPLE_DATA_UNAVAILABLE } from '@/features/capsules/lib/tooltip-copy'

/** Whether a witness this node trusts vouches for the log an answer's chain
 *  comes from (evidencebook#209: a chain that only checks against its
 *  holder's own signatures is never called verified):
 *
 *   - `witnessed`: at least one of their checkpoints carries a witness receipt
 *     that verified under a witness key the operator configured;
 *   - `unwitnessed`: witness keys are configured, and none vouched;
 *   - `no_witness`: no witness key is configured, so nothing was checked;
 *   - `not_recorded`: a remembered result from before this was kept
 *     (`history-memory.ts`), so its standing is unknown. */
export type WitnessStanding = 'witnessed' | 'unwitnessed' | 'no_witness' | 'not_recorded'

/** The standing the plugin's verification reports (its `witnessed` count). */
export function witnessStanding(witnessed: number | undefined): Exclude<WitnessStanding, 'not_recorded'> {
  if (witnessed === undefined) return 'no_witness'
  return witnessed > 0 ? 'witnessed' : 'unwitnessed'
}

/** What asking produced for one row. `at` is when this node asked or when the
 *  other side signed its reply. */
export type AskOutcome =
  | { kind: 'asking'; at: string }
  /** `plain`: the ask never got a reply to check (the tool failed), and
   *  `detail` is a whole plain sentence saying so, shown as is. */
  | { kind: 'no_reply'; at: string; detail: string; plain?: boolean }
  | { kind: 'refused'; at: string; reason: string }
  | { kind: 'no_record'; at: string }
  /** `saved`: whether the plugin kept this record on the node (its id is in
   *  the tool's `held`). Absent where nothing said either way. `witness`:
   *  whether a witness this node trusts vouches for their log; absent is read
   *  as `no_witness`, never as witnessed. */
  | {
      kind: 'record'
      at: string
      evidence: PeerRecomputeState
      saved?: boolean
      witness?: Exclude<WitnessStanding, 'not_recorded'>
    }
  /** Their verified reply carried more than one record that could be their
   *  half of this exchange, and nothing picks one: none is shown as theirs. */
  | { kind: 'ambiguous'; at: string; count: number }

/** Whom to ask and how to name the exchange, read from OUR record of it: the
 *  node that served our request (or that asked us, on a row we served), the
 *  client nonce our record carries, and the exchange's two `effect` digests.
 *  `null` when the node is unknown, or when neither the nonce nor both
 *  digests are. */
export type AskTarget = AskSubject & { peerId: string }

/** The nonce a host-served record carries when the host forwarded none
 *  (`evidence_log::HOST_SERVED_NO_NONCE`). Every such record carries it, so
 *  it names no exchange. */
export const HOST_SERVED_NO_NONCE = 'host-served-no-nonce'

const FULL_ID = /^[0-9a-f]{64}$/
/** Their signed "I hold no such record" (the -00 registry token). */
const NO_SUCH_SUBJECT = 'no_such_subject'
/** They hold the record but no checkpoint covers it yet: a lag, never a
 *  decline. Asking again later can succeed. */
const COVERAGE_LAG = 'coverage_unsatisfiable'

function obj(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : null
}

function str(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null
}

function pocBlock(record: unknown): Record<string, unknown> | null {
  return obj(obj(obj(obj(record)?.model_attestation)?.compute_attestation)?.['x-mesh-poc-v1'])
}

/** The node on the other side of the exchange, as OUR record names it: the
 *  node that served our request, or the one that asked us on a row we
 *  served. `null` when the record names no such node. */
export function otherSideNodeId(record: CapsuleRecord | Record<string, unknown> | null | undefined): string | null {
  const poc = pocBlock(record)
  const provenance = obj(poc?.serving_provenance)
  // A served record names the node that asked as `requesting_party` (sealed
  // from the host's `requested_by_node_id`); older records may carry the raw
  // host field instead.
  const other =
    poc?.role === 'served'
      ? (str(provenance?.requesting_party) ?? str(provenance?.requested_by_node_id))
      : str(provenance?.served_by_node_id)
  const peerId = other?.toLowerCase() ?? null
  return peerId && FULL_ID.test(peerId) ? peerId : null
}

export function askTarget(record: CapsuleRecord | Record<string, unknown> | null | undefined): AskTarget | null {
  const poc = pocBlock(record)
  // A failed exchange binds no digest and has no record of theirs to ask for.
  if (poc?.outcome === 'failed') return null
  const recordedNonce = str(poc?.client_nonce)
  const nonce = recordedNonce === HOST_SERVED_NO_NONCE ? null : recordedNonce
  const effect = obj(obj(record)?.effect)
  const request = str(effect?.request_digest)?.toLowerCase()
  const response = str(effect?.response_digest)?.toLowerCase()
  const digests = request && response && FULL_ID.test(request) && FULL_ID.test(response) ? { request, response } : null
  const peerId = otherSideNodeId(record)
  return peerId && (nonce || digests) ? { peerId, nonce, digests } : null
}

/** The row states where asking can help: their record hasn't arrived. A
 *  declined or no-record row keeps no record ask (product ruling). */
const ASKABLE_KINDS: ReadonlySet<RightCellStateKind> = new Set([
  'open_not_held',
  'open_not_given',
  'open_not_asked',
  'open_asked'
])

/** Why one of the row's two asks can't be sent, or `null` when it can. */
export type RowAskControl = { label: string; disabledReason: string | null }

export type RowAskInput = {
  kind: RightCellStateKind
  /** Whom to ask and how to name the exchange (`askTarget`). */
  target: AskTarget | null
  /** The node on the other side (`otherSideNodeId`): enough for a history ask. */
  peerId: string | null
  /** False where the page can't ask anyone (a saved sample). */
  canAsk: boolean
  roleTag: string
  servedForPay: boolean
  /** The row knows its other side from elsewhere (Pane B), though our record
   *  doesn't name it. */
  otherSideKnown?: boolean
  recordAsk: AskOutcome | null
  historyAsk: { kind: string } | null
}

const FAILED_NO_RECORD_TO_ASK = 'The exchange failed. Failed exchanges are not shared, so there is nothing of theirs to ask for.'
export const ASK_RECORD_LABEL = 'Ask for their record'
export const ASK_RECORD_AGAIN_LABEL = 'Ask again for their record'
export const ASK_HISTORY_LABEL = 'Ask for their history'
export const ASKING_LABEL = 'Asking…'

function nobodyToAsk(roleTag: string, servedForPay: boolean, otherSideKnown: boolean): string {
  if (roleTag !== 'SERVED') return 'Your record doesn’t name the node that answered, so there is no one to ask.'
  // Another node did take part; our record just doesn't say which.
  if (otherSideKnown) return 'Your record doesn’t name the node that asked, so there is no one to ask.'
  return servedForPay
    ? 'Your record doesn’t name the node that paid, so there is no one to ask.'
    : 'No other node took part in this exchange, so there is no one to ask.'
}

/** The row's two asks, always shown: each one either can be sent now, or says
 *  in one line why not. Nothing is offered that would click into nothing. */
export function rowAskControls(input: RowAskInput): { record: RowAskControl; history: RowAskControl } {
  const unavailable = input.canAsk ? null : SAMPLE_DATA_UNAVAILABLE
  const nobody = input.peerId ? null : nobodyToAsk(input.roleTag, input.servedForPay, input.otherSideKnown ?? false)

  let record: RowAskControl
  if (input.recordAsk?.kind === 'asking') {
    record = { label: ASKING_LABEL, disabledReason: 'Waiting for their reply.' }
  } else {
    const label = input.recordAsk || input.kind === 'open_asked' ? ASK_RECORD_AGAIN_LABEL : ASK_RECORD_LABEL
    const settled =
      input.kind === 'closed'
        ? 'Their record is already here and checks out.'
        : input.kind === 'contradicted'
          ? 'Their record is already here; Compare shows where it disagrees.'
          : null
    const unnamed = input.target ? null : 'Your record doesn’t name this exchange in a way they can look up.'
    record = {
      label,
      disabledReason:
        unavailable ??
        (input.roleTag === 'FAILED' ? FAILED_NO_RECORD_TO_ASK : null) ??
        nobody ??
        (ASKABLE_KINDS.has(input.kind) ? unnamed : settled)
    }
  }

  const history: RowAskControl =
    input.historyAsk?.kind === 'asking'
      ? { label: ASKING_LABEL, disabledReason: 'Waiting for their reply.' }
      : { label: ASK_HISTORY_LABEL, disabledReason: unavailable ?? nobody }
  return { record, history }
}

function hexBytes(hex: string): Uint8Array | null {
  if (!/^([0-9a-f]{2})+$/i.test(hex)) return null
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return bytes
}

/** The bytes a refusal's signature covers: its three signed fields as JSON
 *  with sorted keys and no spaces (`capsule_emit.evidence_request.Refusal`). */
export function refusalSigningBody(refusal: { request_digest: string; reason: string; issued_at: string }): Uint8Array {
  const body = JSON.stringify({
    issued_at: refusal.issued_at,
    reason: refusal.reason,
    request_digest: refusal.request_digest
  })
  return new TextEncoder().encode(body)
}

/** The announced key's bytes, when the item names that same key. */
function announcedKeyBytes(namedKeyId: unknown, announcedKeyId: string | null): Uint8Array | null {
  const named = str(namedKeyId)?.toLowerCase()
  if (!announcedKeyId || named !== announcedKeyId.toLowerCase()) return null
  const key = hexBytes(announcedKeyId)
  return key && key.length === 32 ? key : null
}

/** Why a refusal proves nothing, or `null` when it holds: signed under the
 *  announced key, over OUR request. */
export function refusalProblem(
  refusal: Record<string, unknown>,
  announcedKeyId: string | null,
  sentRequestDigest: string
): string | null {
  if (!announcedKeyId) return NO_KEY_DETAIL
  const key = announcedKeyBytes(refusal.key_id, announcedKeyId)
  if (!key) return 'their reply is not signed with the key this node has for them'
  const requestDigest = str(refusal.request_digest)
  if (requestDigest?.toLowerCase() !== sentRequestDigest.toLowerCase()) {
    return 'their reply answers a different request'
  }
  const sig = hexBytes(str(refusal.sig) ?? '')
  const reason = str(refusal.reason)
  const issuedAt = str(refusal.issued_at)
  if (!sig || !reason || !issuedAt) return 'their reply is not signed with the key this node has for them'
  try {
    const body = refusalSigningBody({ request_digest: requestDigest, reason, issued_at: issuedAt })
    return ed25519.verify(sig, body, key) ? null : 'their reply is not signed with the key this node has for them'
  } catch {
    return 'their reply is not signed with the key this node has for them'
  }
}

/** A record's producer signature: a COSE_Sign1 over its own 32-byte
 *  `capsule_id`, under the key this node was told the peer signs with. A
 *  record naming any other key, or a peer with no announced key, fails. */
export function producerSignatureVerifies(record: Record<string, unknown>, announcedKeyId: string | null): boolean {
  const envelope = hexBytes(str(record.signature) ?? '')
  const key = announcedKeyBytes(record.key_id, announcedKeyId)
  const id = hexBytes(str(record.capsule_id) ?? '')
  if (!envelope || !key || !id) return false
  const result = verifyCoseSign1(envelope, key)
  return result.verified && result.payload.length === id.length && result.payload.every((b, i) => b === id[i])
}

export type AskJudges = {
  recomputeIdMatch: (record: Record<string, unknown>, capsuleId: string | null) => Promise<boolean | null>
  producerSignatureVerifies: (record: Record<string, unknown>, announcedKeyId: string | null) => boolean
}

const REAL_JUDGES: AskJudges = { recomputeIdMatch, producerSignatureVerifies }

/** Unpadded base64url, as the interop profile's reply carries bytes in a JSON frame. */
function base64urlBytes(text: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) return null
  try {
    const binary = atob(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4))
    return Uint8Array.from(binary, (c) => c.charCodeAt(0))
  } catch {
    return null
  }
}

/** The records an artifact answer carries, decoded: the artifact is the
 *  envelope's `artifact` (the interop profile's reply: its JSON text as
 *  unpadded base64url), and each served record's body is its line in the
 *  peer's ledger, hex-encoded. Only the leaf indices the verification proved
 *  are kept. */
function artifactRecords(answer: Record<string, unknown>, proven: readonly number[]): Record<string, unknown>[] {
  let artifact: unknown
  try {
    const bytes = typeof answer.artifact === 'string' ? base64urlBytes(answer.artifact) : null
    artifact = bytes ? JSON.parse(new TextDecoder().decode(bytes)) : null
  } catch {
    return []
  }
  const served = obj(artifact)?.records
  if (!Array.isArray(served)) return []
  const out: Record<string, unknown>[] = []
  for (const item of served) {
    const entry = obj(item)
    if (!entry || typeof entry.leaf_index !== 'number' || !proven.includes(entry.leaf_index)) continue
    const bytes = hexBytes(str(entry.body) ?? '')
    if (!bytes) continue
    try {
      const parsed = obj(JSON.parse(new TextDecoder().decode(bytes)))
      if (parsed) out.push(parsed)
    } catch {
      // not a record: skipped
    }
  }
  return out
}

/** Judge the other side's reply for the exchange whose request digest is
 *  `requestDigest`. */
export async function judgeAskReply(
  reply: EvidenceAskReply,
  requestDigest: string | null,
  askedAt: string,
  judges: AskJudges = REAL_JUDGES
): Promise<AskOutcome> {
  if (reply.kind === 'no_answer') return { kind: 'no_reply', at: askedAt, detail: askFailureSentence(reply.message), plain: true }
  const answer = obj(reply.answer)
  const verification = reply.verification
  switch (verification.state) {
    case 'no_announced_key':
      return { kind: 'no_reply', at: askedAt, detail: NO_KEY_DETAIL }
    case 'not_evidence':
      return { kind: 'no_reply', at: askedAt, detail: `their reply did not verify: ${verification.why}` }
    case 'unknown':
      return { kind: 'no_reply', at: askedAt, detail: 'their reply was not verified' }
    case 'refusal': {
      const problem = answer ? refusalProblem(answer, reply.announcedKeyId, reply.requestDigest) : 'no refusal'
      if (problem || answer?.reason !== verification.reason) {
        return { kind: 'no_reply', at: askedAt, detail: problem ?? 'their reply was not verified' }
      }
      const at = str(answer?.issued_at) ?? askedAt
      if (verification.reason === COVERAGE_LAG) {
        return { kind: 'no_reply', at: askedAt, detail: 'they hold the record but cannot prove it yet; ask again later' }
      }
      return verification.reason === NO_SUCH_SUBJECT
        ? { kind: 'no_record', at }
        : { kind: 'refused', at, reason: verification.reason }
    }
    case 'artifact': {
      const receipts = answer ? artifactRecords(answer, verification.records) : []
      const candidates = theirHalfCandidates(receipts, requestDigest)
      if (candidates.length === 0) return { kind: 'no_reply', at: askedAt, detail: 'their reply carried no record' }
      if (candidates.length > 1) return { kind: 'ambiguous', at: askedAt, count: candidates.length }
      const receipt = candidates[0]
      const idMatch = await judges.recomputeIdMatch(receipt, str(receipt.capsule_id))
      const receiptId = str(receipt.capsule_id)
      return {
        kind: 'record',
        at: askedAt,
        saved: receiptId !== null && reply.held.includes(receiptId),
        witness: witnessStanding(verification.witnessed),
        evidence: {
          status: 'found',
          idMatch,
          signatureOk: judges.producerSignatureVerifies(receipt, reply.announcedKeyId),
          peerRecord: receipt,
          fetch: () => {}
        }
      }
    }
  }
}

/** The records in their reply that could be their half of this exchange:
 *  those whose request digest is ours (all of them when none is), and among
 *  those the half they SERVED when there is one. One candidate is judged by
 *  the row gate; more than one is ambiguous, never resolved by order. */
export function theirHalfCandidates(
  receipts: readonly Record<string, unknown>[],
  requestDigest: string | null
): Record<string, unknown>[] {
  const matching = receipts.filter((candidate) => obj(candidate.effect)?.request_digest === requestDigest)
  const pool = matching.length > 0 ? matching : [...receipts]
  const served = pool.filter((candidate) => pocBlock(candidate)?.role === 'served')
  return served.length > 0 ? served : pool
}

export const NO_KEY_DETAIL = 'this node has no key for them, so their reply can’t be checked'

/** The ask's tool failed because the node isn't reachable: it left the mesh
 *  (`mesh_evidence_bridge.rs`: "could not reach peer", or the host's "not
 *  routable"). */
export const NOT_ON_MESH = 'That node isn’t on the mesh now, so it can’t be asked.'
/** Any other failure of the ask itself. The tool's message is never shown:
 *  it can be raw JSON or an internal error. */
export const ASK_DID_NOT_GO_THROUGH = 'The ask didn’t go through, so there is no reply to check yet.'

/** A tool error, in one plain sentence (`no_answer`). */
export function askFailureSentence(message: string): string {
  return /could not reach peer|not routable/i.test(message) ? NOT_ON_MESH : ASK_DID_NOT_GO_THROUGH
}

/** The -00 refusal reasons a record ask can get back
 *  (`evidence_answer.rs`), in plain words. `no_such_subject` and
 *  `coverage_unsatisfiable` are not declines (`judgeAskReply`). A token this
 *  page has no words for is never echoed: the peer controls it. */
const RECORD_REFUSAL_WORDS: Record<string, string> = {
  not_authorized: 'their sharing settings don’t let them send it to this node',
  policy_declined: 'their node’s limits on what it sends ruled it out',
  deadline_unmet: 'they couldn’t answer in time',
  request_malformed: 'they couldn’t read the request',
  retention_expired: 'they no longer keep it',
  derivation_unsupported: 'their node can’t produce that answer'
}

export function recordRefusalWords(reason: string): string {
  return RECORD_REFUSAL_WORDS[reason] ?? 'for a reason this page can’t name'
}

/** Why a record of theirs is not verified, in a few words. */
export function recordProblems(evidence: PeerRecomputeState): string {
  const { idMatch, signatureOk } = evidence
  return [
    idMatch === true ? null : idMatch === false ? 'its id doesn’t match its contents' : 'its id couldn’t be checked',
    signatureOk === true ? null : 'it is not signed with the key this node has for them'
  ]
    .filter((p): p is string => p !== null)
    .join('; ')
}

const SIGNED_FOR_THIS_REQUEST = 'Their reply is verified: signed with the key this node has for them, for this request'

const IN_THEIR_LOG = 'it is in their log, under a checkpoint signed with the key this node has for them'

/** The line a row shows once its ask is answered: whether the reply was
 *  verified, and if not, why. `null` while the ask is in flight. A record's
 *  note also carries its `witness` standing: only a witnessed one is
 *  `verified`, since without a witness their log could be a private copy. */
export function askReplyNote(
  outcome: AskOutcome
): { verified: boolean; text: string; witness?: Exclude<WitnessStanding, 'not_recorded'> } | null {
  switch (outcome.kind) {
    case 'asking':
      return null
    case 'no_reply':
      return { verified: false, text: outcome.plain ? outcome.detail : `Their reply is not verified: ${outcome.detail}` }
    case 'refused':
      return {
        verified: true,
        text: `Signed refusal, ${formatExchangeTimestamp(outcome.at)}: ${recordRefusalWords(outcome.reason)}. ${SIGNED_FOR_THIS_REQUEST}.`
      }
    case 'no_record':
      return { verified: true, text: SIGNED_FOR_THIS_REQUEST }
    case 'record': {
      // The plugin proved the record is in their log; the record itself is
      // verified only if its id recomputes AND it is signed with their
      // announced key. Anything less is said, never rounded up.
      if (isVerifiedRecord(outcome.evidence)) {
        const witness = outcome.witness ?? 'no_witness'
        switch (witness) {
          case 'witnessed':
            return {
              verified: true,
              witness,
              text: 'Their reply is verified: the record is in their log, under a checkpoint signed with the key this node has for them, and a witness this node trusts holds their checkpoint'
            }
          case 'unwitnessed':
            return {
              verified: false,
              witness,
              text: `Their record checks against their own signatures only: ${IN_THEIR_LOG}, but no witness this node trusts has vouched for that log, so it could be a private copy`
            }
          case 'no_witness':
            return {
              verified: false,
              witness,
              text: `Their record checks against their own signatures only: ${IN_THEIR_LOG}. This node has no witness configured to check it against, so it could be a private copy`
            }
        }
      }
      return {
        verified: false,
        text: `Their record is in their log, but it is not verified: ${recordProblems(outcome.evidence)}`
      }
    }
    case 'ambiguous':
      return {
        verified: false,
        text: `Their reply carried ${outcome.count} records that could be theirs for this exchange; none is shown as theirs`
      }
  }
}

/** A row's asks for their record: the latest outcome, the newest verified
 *  claim (their signed refusal or "no record", `newerClaim`), and the latest
 *  record that can give a verdict. Each is kept apart, so a later reply of another kind -- a failure,
 *  or a record that confirms nothing -- never erases what an earlier reply
 *  proved. `row-evidence.ts` weighs them. */
export type RowAsk = {
  latest: AskOutcome
  claim: Extract<AskOutcome, { kind: 'refused' | 'no_record' }> | null
  /** The latest record that gives this row a verdict. */
  record: Extract<AskOutcome, { kind: 'record' }> | null
}

/** Which of two verified claims to keep: the newer by signed time when both
 *  carry a full RFC 3339 time; otherwise the stored one, unless the new one
 *  says something different (a refusal vs "no record"). */
function newerClaim(stored: RowAsk['claim'], incoming: NonNullable<RowAsk['claim']>): NonNullable<RowAsk['claim']> {
  if (!stored) return incoming
  const storedAt = fullTimeInstant(stored.at)
  const incomingAt = fullTimeInstant(incoming.at)
  if (storedAt !== null && incomingAt !== null) return incomingAt >= storedAt ? incoming : stored
  return incoming.kind !== stored.kind ? incoming : stored
}

/** `localRecord` is our record of the exchange: what decides whether a
 *  record they sent gives this row a verdict (`recordVerdict`, the same
 *  judgement `judgeRow` uses). */
export function settleRowAsk(
  previous: RowAsk | null | undefined,
  outcome: AskOutcome,
  localRecord: CapsuleRecord | null | undefined
): RowAsk {
  const claim =
    outcome.kind === 'refused' || outcome.kind === 'no_record'
      ? newerClaim(previous?.claim ?? null, outcome)
      : (previous?.claim ?? null)
  // Only a record that gives this row a verdict (Confirmed or Disagree) is
  // kept; one that reaches none -- even validly signed, from another provider
  // or for another exchange -- only updates `latest`.
  const keeps =
    outcome.kind === 'record' && recordVerdict(outcome.evidence, localRecord, 'asked').kind !== 'no_verdict'
  const record = keeps ? outcome : (previous?.record ?? null)
  return { latest: outcome, claim, record }
}
