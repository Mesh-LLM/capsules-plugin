// What a saved History page checks about the node's answer when it opens.
//
// The answer is a node's `history_card/1` reply (evidence-interop/0): its
// artifact lists the node's checkpoints, each with the proof that it extends
// the one before. The page re-checks, offline and in the page itself, what
// this file can check with the browser build of `@action-state-group/cll`:
// the artifact is the bytes the reply's digest names, every checkpoint is
// signed by the key the reply names as its responder, each consistency proof
// holds, the list starts the stream and each checkpoint extends the one
// before, and the last one is the anchor the artifact names.
//
// It does NOT check, and says so on the page, what only the node's own
// checker runs: the witness receipts, the reply envelope's signature, and
// the digest of the request it answers (cll 0.3.0 has no browser verifier for
// those). A page never calls those checks passed.
//
// This file is bundled twice: into the Evidence page (tests) and, as an IIFE,
// into every saved page (`saved-pages.ts`), so it imports only the cll
// browser build and uses no DOM.
import { checkpointMetadata, leafCount, verifyCheckpoint, verifyConsistency } from '@cll-browser'

/** The most checkpoints a node puts in one card (`MAX_ANSWER_CHECKPOINTS`,
 *  crates/evidence-plugin/src/evidence_answer.rs): a longer list is not one. */
const MAX_CHECKPOINTS = 1024

export type CheckStatus = 'pass' | 'fail' | 'not_run'

export type Check = { id: string; status: CheckStatus; detail: string }

export type HistoryVerdict = {
  /** `answered`: the node gave its card; `refused`: it signed a refusal;
   *  `unreadable`: the bytes are neither. */
  kind: 'answered' | 'refused' | 'unreadable'
  /** True only when `kind` is `answered` and no check failed. */
  verified: boolean
  checks: Check[]
  /** The checkpoints the card lists, when it was read. */
  checkpoints: { size: number; time: string; anchor: string }[]
  /** The refusal's reason, for a refusal. */
  reason?: string
  /** The key every checkpoint was checked under: the one the reply names as
   *  its responder. Whether it is the node's is not checked. */
  keyId?: string
  /** Which form was read: the node's card alone, or its Service History. */
  form?: 'history_card' | 'service_history'
  /** A Service History's counts, as the node states them (self reported). */
  counts?: PeriodCount[]
}

/** One closed period of a Service History: each cell as text, as stated. */
export type PeriodCount = { from: string; to: string; cells: { what: string; value: string }[] }

export const PERIOD_COUNTS_NOT_RUN: Check = {
  id: 'period_counts',
  status: 'not_run',
  detail:
    'The counts were not checked against the node’s records or its period policy. They are the node’s own statement, shown as given.'
}

// RFC 8785 for the values a card holds: null, strings, arrays, objects.
function jcs(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`
  if (value && typeof value === 'object') {
    const o = value as Record<string, unknown>
    return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${jcs(o[k])}`).join(',')}}`
  }
  return JSON.stringify(value)
}

function periodCounts(raw: unknown): PeriodCount[] {
  const periods = object(raw) && Array.isArray(object(raw)!.periods) ? (object(raw)!.periods as unknown[]) : []
  return periods.flatMap((p) => {
    const period = object(p)
    if (!period || typeof period.from !== 'string' || typeof period.to !== 'string' || !Array.isArray(period.cells)) return []
    const cells = period.cells.flatMap((c) => {
      const cell = object(c)
      if (!cell) return []
      const model = object(cell.dimension)?.model
      const what = typeof model === 'string' ? `model ${model}` : 'all models'
      const value =
        typeof cell.value === 'number'
          ? String(cell.value)
          : cell.suppressed === 'complementary'
            ? 'withheld (showing it would let a count under the floor be worked out)'
            : cell.suppressed === 'below_floor'
              ? 'withheld (below the floor)'
              : 'no count stated'
      return [{ what, value }]
    })
    return [{ from: period.from, to: period.to, cells }]
  })
}

/** The checks this page cannot run, always listed, whatever else passed. */
export const NOT_RUN: readonly Check[] = [
  { id: 'witness_receipts', status: 'not_run', detail: 'Witness receipts were not checked: this page has no verifier for them.' },
  {
    id: 'envelope_signature',
    status: 'not_run',
    detail: 'The signature over the reply itself was not checked: this page has no verifier for it.'
  },
  {
    id: 'key_is_nodes',
    status: 'not_run',
    detail: 'That this key is the node’s was not checked: compare it with the node’s published commitment.'
  },
  {
    id: 'request_binding',
    status: 'not_run',
    detail: 'That the reply answers a particular request was not checked: the page does not hold the request.'
  }
]

const hexToBytes = (hex: string): Uint8Array | null => {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) return null
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

const bytesToHex = (bytes: Uint8Array): string => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')

export const base64urlToBytes = (text: string): Uint8Array | null => {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) return null
  const std = text.replace(/-/g, '+').replace(/_/g, '/')
  const padded = std + '='.repeat((4 - (std.length % 4)) % 4)
  try {
    const raw = atob(padded)
    return Uint8Array.from(raw, (c) => c.charCodeAt(0))
  } catch {
    return null
  }
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const copy = new Uint8Array(bytes)
  return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', copy)))
}

// A consistency proof is a CBOR array [from, to, [path per old peak], [right
// peaks]] (profile 6.2.1 step 13). Definite lengths only, which is all the
// node writes; anything else is "does not hold".
type Cbor = number | Uint8Array | Cbor[]

function decodeCbor(bytes: Uint8Array): Cbor | null {
  let at = 0
  const item = (): Cbor => {
    if (at >= bytes.length) throw new Error('end')
    const initial = bytes[at++]
    const major = initial >> 5
    const info = initial & 31
    let length: number
    if (info < 24) length = info
    else if (info === 24) length = bytes[at++]
    else if (info === 25) length = (bytes[at++] << 8) | bytes[at++]
    else if (info === 26) length = ((bytes[at++] << 24) | (bytes[at++] << 16) | (bytes[at++] << 8) | bytes[at++]) >>> 0
    else throw new Error('length')
    if (major === 0) return length
    if (major === 2) {
      if (at + length > bytes.length) throw new Error('end')
      const out = bytes.slice(at, at + length)
      at += length
      return out
    }
    if (major === 4) {
      if (length > 4096) throw new Error('long')
      const out: Cbor[] = []
      for (let i = 0; i < length; i++) out.push(item())
      return out
    }
    throw new Error('major')
  }
  try {
    const value = item()
    return at === bytes.length ? value : null
  } catch {
    return null
  }
}

/** How many peaks of the MMR of `newSize` nodes hold a leaf of the MMR of
 *  `oldSize` nodes: peaks run from the largest subtree down, each covering
 *  the next run of leaves. */
function peaksCoveringOldLeaves(oldSize: bigint, newSize: bigint): number | null {
  const oldLeaves = leafCount(oldSize)
  let remaining = leafCount(newSize)
  if (oldLeaves === undefined || remaining === undefined) return null
  let start = 0n
  let covering = 0
  for (let bit = 62n; bit >= 0n; bit--) {
    const span = 1n << bit
    if (remaining & span) {
      if (start < oldLeaves) covering++
      start += span
      remaining -= span
    }
  }
  return covering
}

const isHashes = (value: Cbor | undefined): value is Uint8Array[] =>
  Array.isArray(value) && value.every((h) => h instanceof Uint8Array && h.length === 32)

type Link = { cose: Uint8Array; digest: string; size: bigint; root: string; previousSize: bigint; previousRoot: string; peaks: Uint8Array[]; logId: string; keyId: string; time: string }

const object = (value: unknown): Record<string, unknown> | null =>
  value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : null

/** Check one reply, given as the exact text the node served. */
export async function verifyHistoryReply(replyText: string): Promise<HistoryVerdict> {
  const unreadable = (detail: string): HistoryVerdict => ({
    kind: 'unreadable',
    verified: false,
    checks: [{ id: 'readable', status: 'fail', detail }],
    checkpoints: []
  })
  let reply: Record<string, unknown> | null
  try {
    reply = object(JSON.parse(replyText))
  } catch {
    reply = null
  }
  if (!reply) return unreadable('The saved answer is not a JSON object.')

  if (typeof reply.reason === 'string' && reply.artifact_digest === undefined) {
    return {
      kind: 'refused',
      verified: false,
      checks: [
        { id: 'refusal', status: 'not_run', detail: 'The node declined to answer. The signature on its refusal was not checked.' }
      ],
      checkpoints: [],
      reason: reply.reason
    }
  }

  const checks: Check[] = []
  const fail = (id: string, detail: string): HistoryVerdict => ({
    kind: 'answered',
    verified: false,
    checks: [...checks, { id, status: 'fail', detail }, ...NOT_RUN],
    checkpoints: []
  })

  const artifactText = reply.artifact
  const stated = reply.artifact_digest
  const responder = reply.responder
  if (typeof artifactText !== 'string' || typeof stated !== 'string' || typeof responder !== 'string') {
    return unreadable('The saved answer names no artifact, digest or responder.')
  }
  const artifactBytes = base64urlToBytes(artifactText)
  if (!artifactBytes) return fail('artifact_digest', 'The artifact is not readable.')
  if ((await sha256Hex(artifactBytes)) !== stated) return fail('artifact_digest', 'The artifact is not the bytes its digest names.')
  checks.push({ id: 'artifact_digest', status: 'pass', detail: 'The artifact is the bytes its digest names.' })

  let artifact: Record<string, unknown> | null
  try {
    artifact = object(JSON.parse(new TextDecoder().decode(artifactBytes)))
  } catch {
    artifact = null
  }
  if (!artifact) return fail('card', 'The artifact is not readable.')
  // A Service History embeds the node's card as a member; a direct answer is the card.
  const embedded = object(artifact.history_card)
  let card: Record<string, unknown> = artifact
  let counts: PeriodCount[] | undefined
  if (embedded) {
    const cardDigest = await sha256Hex(new TextEncoder().encode(jcs(embedded)))
    if (cardDigest !== artifact.history_card_digest) {
      return fail('card_digest', 'The history card inside is not the bytes its digest names.')
    }
    checks.push({ id: 'card_digest', status: 'pass', detail: 'The history card inside matches its digest.' })
    if (artifact.anchor !== embedded.anchor || artifact.evidence_stream !== embedded.evidence_stream) {
      return fail('card', 'The history card inside names another anchor or log than the answer.')
    }
    // The answer names one derivation, the artifact says it carries the card and the counts, and
    // the card is for the same subject (the node's own checker holds the same).
    const declared = artifact.declared
    if (
      typeof reply.derivation !== 'string' ||
      artifact.derivation !== reply.derivation ||
      !Array.isArray(declared) ||
      !declared.includes('history_card') ||
      !declared.includes('period_counts') ||
      jcs(embedded.subject) !== jcs(artifact.subject)
    ) {
      return fail('card', 'The artifact is not a Service History for the card inside it.')
    }
    card = embedded
    counts = periodCounts(artifact.period_counts)
  } else if (reply.derivation !== 'history_card/1') {
    return fail('card', 'The artifact is not a history_card/1 card.')
  }
  const history = Array.isArray(card.history) ? card.history : null
  if (!history || history.length === 0 || history.length > MAX_CHECKPOINTS) {
    return fail('card', 'The artifact is not a history card.')
  }
  if (card.derivation !== 'history_card/1') return fail('card', 'The artifact is not a history_card/1 card.')

  const links: Link[] = []
  for (let i = 0; i < history.length; i++) {
    const entry = object(history[i])
    const statement = entry && typeof entry.checkpoint === 'string' ? hexToBytes(entry.checkpoint) : null
    if (!entry || !statement) return fail('checkpoints', `Checkpoint ${i + 1} is not readable.`)
    const meta = (await verifyCheckpoint(statement)) ? await checkpointMetadata(statement) : undefined
    if (!meta) return fail('checkpoints', `Checkpoint ${i + 1} does not verify.`)
    if (meta.keyId !== responder) return fail('checkpoints', `Checkpoint ${i + 1} is not signed by the key that answered.`)
    links.push({
      cose: statement,
      digest: await sha256Hex(statement),
      size: meta.size,
      root: meta.root,
      previousSize: meta.previousSize,
      previousRoot: meta.previousRoot,
      peaks: [...meta.peaks],
      logId: meta.logId,
      keyId: meta.keyId,
      time: meta.timestamp
    })
  }
  checks.push({
    id: 'checkpoints',
    status: 'pass',
    detail: `All ${links.length} checkpoints verify and are signed by the key that answered.`
  })

  const first = links[0]
  if (first.previousSize !== 0n || first.previousRoot !== '') return fail('chain', 'The list does not start at the beginning of the log.')
  for (let i = 1; i < links.length; i++) {
    const prev = links[i - 1]
    const next = links[i]
    if (next.previousSize !== prev.size || next.previousRoot !== prev.root || next.logId !== prev.logId || next.size <= prev.size) {
      return fail('chain', `Checkpoint ${i + 1} does not extend the one before it.`)
    }
    const entry = object(history[i])
    const proofHex = entry && typeof entry.consistency_from_previous === 'string' ? entry.consistency_from_previous : null
    const proofBytes = proofHex ? hexToBytes(proofHex) : null
    const decoded = proofBytes ? decodeCbor(proofBytes) : null
    if (!Array.isArray(decoded) || decoded.length !== 4) return fail('consistency', `The proof for checkpoint ${i + 1} is missing or unreadable.`)
    const [from, to, paths, right] = decoded
    if (typeof from !== 'number' || typeof to !== 'number' || BigInt(from) !== prev.size || BigInt(to) !== next.size) {
      return fail('consistency', `The proof for checkpoint ${i + 1} is for other sizes.`)
    }
    if (!Array.isArray(paths) || !paths.every(isHashes) || !isHashes(right)) {
      return fail('consistency', `The proof for checkpoint ${i + 1} is malformed.`)
    }
    // The proof's `right` peaks are the new peaks no old peak folds into: the
    // tail of the signed checkpoint's own peaks, never anything else.
    // How many is fixed by the sizes: the new peaks that cover no old leaf.
    const covering = peaksCoveringOldLeaves(prev.size, next.size)
    if (covering === null) return fail('consistency', `Checkpoint ${i + 1} has a size no log can have.`)
    const expectedRight = next.peaks.length - covering
    const tail = next.peaks.slice(next.peaks.length - right.length)
    if (
      right.length !== expectedRight ||
      right.length > next.peaks.length ||
      !right.every((h, k) => bytesToHex(h) === bytesToHex(tail[k]))
    ) {
      return fail('consistency', `The proof for checkpoint ${i + 1} names peaks the checkpoint does not have.`)
    }
    const oldRoot = hexToBytes(prev.root)
    const newRoot = hexToBytes(next.root)
    if (!oldRoot || !newRoot) return fail('consistency', `Checkpoint ${i + 1} names no readable root.`)
    const holds = await verifyConsistency(oldRoot, newRoot, {
      oldSize: prev.size,
      newSize: next.size,
      oldPeaks: prev.peaks,
      witness: paths as Uint8Array[][],
      newPeaks: next.peaks
    }).catch(() => false)
    if (!holds) return fail('consistency', `The proof that checkpoint ${i + 1} extends the one before does not hold.`)
  }
  checks.push({
    id: 'chain',
    status: 'pass',
    detail:
      links.length === 1
        ? 'The log has one checkpoint, and it starts the log.'
        : `The list starts the log, each checkpoint extends the one before, and all ${links.length - 1} consistency proofs hold.`
  })

  const last = links[links.length - 1]
  const anchor = object(reply.anchor)
  if (artifact.anchor !== last.digest || !anchor || anchor.digest !== last.digest) {
    return fail('anchor', 'The last checkpoint is not the anchor the answer names.')
  }
  if (artifact.evidence_stream !== last.logId) return fail('anchor', 'The answer names another log than its checkpoints.')
  checks.push({ id: 'anchor', status: 'pass', detail: 'The last checkpoint is the anchor the answer names, for the log it names.' })

  return {
    kind: 'answered',
    verified: true,
    checks: [...checks, ...(counts ? [PERIOD_COUNTS_NOT_RUN] : []), ...NOT_RUN],
    checkpoints: links.map((l) => ({ size: Number(l.size), time: l.time, anchor: l.digest })),
    keyId: last.keyId,
    form: counts ? 'service_history' : 'history_card',
    ...(counts ? { counts } : {})
  }
}
