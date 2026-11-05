// Pure view-model derivation for a Pane B row.
// Kept separate from the rendering components so the honesty-backbone
// invariants (denominators always present, NOT_CHECKED never summarized as
// corroborated, with-you and their-chain never summed) are unit-testable
// without mounting a component.
import type { PaneBConfirmedSibling, PaneBRow, PaneCRow } from '@/features/capsules/api/sidecarTypes'
import { deriveRightCellState } from '@/features/capsules/lib/exchange-row-state'
import type { PeerMeshStatus } from '@/features/capsules/lib/peer-mesh-status'
import { parseVerdict } from '@/features/capsules/lib/adjudication-view'
import { peerSettlementText } from '@/features/capsules/lib/settlement-view'
import { PEER_ATTENTION, PEER_COLUMN_TOOLTIPS } from '@/features/capsules/lib/tooltip-copy'

export const STATE_NOT_CHECKED = 'NOT_CHECKED'
export const STATE_CONTRADICTED = 'contradicted'
export const STATE_FAILED = 'failed'
export const STATE_REFUSED = 'refused'
export const STATE_VERIFIED = 'verified'

/** `null` means this row carries no counterparty identity at all -- pane-b's
 *  own honest signal that these exchanges are unattributed, not that one
 *  peer's identity failed to resolve (design chooser-v1 §7 S1.1). Never
 *  invent a placeholder string for this case; callers render "counterparty
 *  not recorded" / exclude the row from the Peers list instead. */
export function peerDisplayId(row: PaneBRow): string | null {
  return row.peer_id ?? row.node?.peer_id ?? null
}

/** True when this row has no counterparty identity (see `peerDisplayId`) --
 *  the Peers list never renders a card for these; they're rolled into the
 *  unattributed-exchanges line instead. */
export function isUnattributedPeerRow(row: PaneBRow): boolean {
  return peerDisplayId(row) === null
}

/** The Peers-section headline for exchanges with no counterparty evidence
 *  at all -- a stated fact (R-C), never phrased as pending work. */
export function unattributedExchangesLine(count: number): string {
  const subject = count === 1 ? 'exchange has' : 'exchanges have'
  return `${count} ${subject} no other side recorded yet. They appear under Exchanges.`
}

// ---------------------------------------------------------------------------
// Peer identity aliases (D3) -- one
// row per peer, joined on the signing key, with the other id spaces shown as
// ALIASES on that row. Only evidence-backed aliases render; a node-id-only
// row (no signed record from that node yet) says so, and names the key this
// node was told that node signs with when there is one, instead of
// pretending the spaces are one.
// ---------------------------------------------------------------------------

export type PeerIdentityAliases = { signingKeyId: string | null; endpointId: string | null; nodeId: string | null }

function nonEmpty(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null
}

export function peerIdentityAliases(row: PaneBRow): PeerIdentityAliases {
  const identity = row.identity ?? null
  return {
    signingKeyId: nonEmpty(identity?.signing_key_id),
    endpointId: nonEmpty(identity?.endpoint_id),
    nodeId: nonEmpty(identity?.node_id)
  }
}

/** The node id of a row known only from this node's own records (a record
 *  naming the server it routed to), with no signed record from that node
 *  yet: what to look up an announced key for. `null` otherwise. */
export function unlinkedNodeId(row: PaneBRow): string | null {
  const { signingKeyId, endpointId, nodeId } = peerIdentityAliases(row)
  return !signingKeyId && nodeId && !endpointId ? nodeId : null
}

/** The one alias line under a peer row's id: "signed by <key16> · node
 *  <id16>… · endpoint <id>" for a key-joined peer (only the aliases the
 *  evidence carries), the unlinked note for a node-id-only row, and `null`
 *  when the row carries no identity evidence at all. `announcedKeyId` is the
 *  key this node was told the unlinked node signs with (the plugin's
 *  `peer-key` route), or `null` when none is. The route merges the host's
 *  announced keys with the operator's `CAPSULES_PEER_KEYS` and doesn't say
 *  which one a key came from, so the line claims no source. */
export function peerAliasLine(row: PaneBRow, announcedKeyId: string | null = null): string | null {
  const { signingKeyId, endpointId, nodeId } = peerIdentityAliases(row)
  if (!signingKeyId) {
    if (!unlinkedNodeId(row)) return null
    return announcedKeyId
      ? `Known from your records · its signing key ${announcedKeyId.slice(0, 16)} is known to this node`
      : 'Known from your records · no signed record from them yet'
  }
  const parts = [`signed by ${signingKeyId.slice(0, 16)}`]
  if (nodeId) parts.push(`node ${nodeId.slice(0, 16)}…`)
  // Never a 64-hex id on the row face (§7.4): the full id is in the drill.
  if (endpointId) parts.push(`endpoint ${endpointId.length > 16 ? `${endpointId.slice(0, 16)}…` : endpointId}`)
  return parts.join(' · ')
}

/** Used by the modal's Overview tab (`PeerInspector`) for the self-reported
 *  model/quant/context line -- the summary table no longer renders this
 *  (accountability, not operational-announcement),
 *  but the deep-dive inspector still does. */
export function meshMetaLine(meshStatus: PeerMeshStatus | null): string | null {
  if (!meshStatus) return null
  const parts = [
    meshStatus.modelName,
    meshStatus.quant,
    meshStatus.contextLengthK != null ? `${meshStatus.contextLengthK}k ctx` : null
  ].filter((part): part is string => Boolean(part))
  return parts.length > 0 ? parts.join(' · ') : null
}

// ---------------------------------------------------------------------------
// With-you (verifiable, front) -- never summed with their-chain facts.
// Still used by the modal's Overview tab (`PeerInspector`).
// ---------------------------------------------------------------------------

export type WithYouCounts = { requested: number; served: number; confirmed: number }

/** `requested`/`served` from `role_and_count_cell` (direction of exchange,
 *  never a trust signal); `confirmed` from the ONE gate
 *  (`confirmedByOtherSide`, the same figure the Peers table's Confirmed
 *  column renders) -- NEVER `pair_cell.verified`, which no native payload
 *  populates (always 0 live), so the inspector Overview used to contradict
 *  the table on the same peer (fold-in
 *  finding 1). One predicate, one number, two surfaces. */
export function withYouCounts(row: PaneBRow): WithYouCounts {
  return {
    requested: row.role?.you_to_them_count ?? 0,
    served: row.role?.them_to_you_count ?? 0,
    confirmed: confirmedByOtherSide(row).confirmed
  }
}

export function withYouCountsText(counts: WithYouCounts): string {
  return `${counts.requested} requested · ${counts.served} served · ${counts.confirmed} saved as confirmed`
}

// ---------------------------------------------------------------------------
// Adjudication -- always carries a denominator; NOT_CHECKED is never a
// silent pass.
// ---------------------------------------------------------------------------

export type AdjudicationSummary = {
  checked: number
  denominator: number
  corroborated: number
  contradicted: number
  inconclusive: number
  notChecked: boolean
}

/** `denominator` is `exchange_count` (every exchange this row has with the
 *  peer) -- `verdicts_cell` draws its tally from adjudications naming ANY
 *  of this peer's capsule ids, not only the requested-by-you half, so a
 *  narrower denominator would overclaim scope. */
export function adjudicationSummary(row: PaneBRow): AdjudicationSummary {
  // The referee-signed verdicts about this peer, when the plugin sends them:
  // the only verdicts the page counts. A not-comparable ruling isn't a
  // judgment, so it isn't counted as checked.
  const referee = row.referee_verdicts
  if (referee) {
    const corroborated = referee.corroborated?.verdict_capsule_ids.length ?? 0
    const contradicted = referee.contradicted?.verdict_capsule_ids.length ?? 0
    const inconclusive = referee.inconclusive?.verdict_capsule_ids.length ?? 0
    const checked = corroborated + contradicted + inconclusive
    return {
      checked,
      denominator: row.exchange_count ?? 0,
      corroborated,
      contradicted,
      inconclusive,
      notChecked: checked === 0
    }
  }
  const tally = row.verdicts?.tally
  const corroborated = tally?.corroborated ?? 0
  const contradicted = tally?.contradicted ?? 0
  const inconclusive = tally?.inconclusive ?? 0
  const checked = corroborated + contradicted + inconclusive
  const notChecked = row.verdicts?.state === STATE_NOT_CHECKED || checked === 0
  return {
    checked,
    denominator: row.exchange_count ?? 0,
    corroborated,
    contradicted,
    inconclusive,
    notChecked
  }
}

/** Never returns a corroborated-sounding sentence when `notChecked` is
 *  true -- that branch is checked first and returns before the tally is
 *  ever read. */
export function adjudicationSummaryText(summary: AdjudicationSummary): string {
  if (summary.notChecked) {
    return 'Not yet checked — no adjudication sealed for this peer yet.'
  }
  const parts: string[] = []
  if (summary.corroborated) parts.push(`${summary.corroborated} corroborated`)
  if (summary.contradicted) parts.push(`${summary.contradicted} contradicted`)
  if (summary.inconclusive) parts.push(`${summary.inconclusive} inconclusive`)
  return `${summary.checked} of ${summary.denominator} adjudicated · ${parts.join(' · ')}`
}

// ---------------------------------------------------------------------------
// Confirmed by the other side -- routed through the ONE gate
//, the SAME predicate Pane C uses. A peer's
// pushed halves arrive correlated + provenance-carrying in
// `row.confirmed_siblings` (`capsule_panes_native.rs`), each supplying the two
// gate inputs (`theirs.signature_ok` + `digest_match`). Every sibling is run
// through `deriveRightCellState` -- never a second, browser-peer-fetch
// predicate on `history` -- and a `closed` verdict counts as confirmed. A peer
// with no correlated pushed half has an empty list, which the gate reads as
// "not confirmed": the honest "waiting for the other side" state, never a
// fabricated zero and never phrased as pending work the user must trigger.
// ---------------------------------------------------------------------------

export type ConfirmedByOtherSide = { confirmed: number; total: number; note: string | null }

/** Runs one supplied sibling through the ONE gate as a minimal Pane C row --
 *  the gate reads only `mine.record` + `theirs` (body, door verdict, in-browser
 *  id recompute) here, so the rest of a full `PaneCRow` is stubbed honestly. */
function siblingGateState(sibling: PaneBConfirmedSibling): ReturnType<typeof deriveRightCellState> {
  const row: PaneCRow = {
    exchange_key: '',
    role_tag: '',
    header_state: '',
    properties: null,
    has_issue: false,
    mine: sibling.mine ?? { state: 'present-unverified', capsule_id: null },
    theirs: sibling.theirs,
    unilateral: false,
    digest_match: sibling.digest_match,
    timestamp: null
  }
  return deriveRightCellState(row)
}

export function confirmedByOtherSide(row: PaneBRow): ConfirmedByOtherSide {
  const total = row.exchange_count ?? 0
  const siblings = row.confirmed_siblings ?? []
  const confirmed = siblings.filter((sibling) => siblingGateState(sibling).kind === 'closed').length
  const contradicted = siblings.filter((sibling) => siblingGateState(sibling).kind === 'contradicted').length
  // A confirmation the gate reads as CONTRADICTED is a disagreement, not a
  // silent zero -- name it so the count and the alarm can never diverge.
  if (contradicted > 0) {
    return { confirmed, total, note: `${contradicted} contradicted` }
  }
  // Nothing the other side sent has closed through the gate yet -- covers both
  // "no half received" and "a half received but not yet verifiable". Stated as
  // a fact, never as pending work the user has to go and do.
  if (confirmed === 0) {
    return { confirmed: 0, total, note: 'none confirmed yet' }
  }
  return { confirmed, total, note: null }
}

// ---------------------------------------------------------------------------
// Match -- the clean/mismatch tally of the halves the other side actually
// sent, derived through the SAME ONE gate: a
// `closed` sibling is clean (digests cite our half), a `contradicted` sibling
// is a mismatch. `clean`/`mismatch` always both render (even at zero);
// `contradicted` (the adjudication tally) only appears when nonzero -- a peer
// with no contradiction has never had one, not "0 of them", the same
// zero-is-a-fact-not-silence discipline as `adjudicationSummaryText`.
// ---------------------------------------------------------------------------

export type MatchTally = { clean: number; mismatch: number; contradicted: number }

export function matchTally(row: PaneBRow): MatchTally {
  const siblings = row.confirmed_siblings ?? []
  return {
    clean: siblings.filter((sibling) => siblingGateState(sibling).kind === 'closed').length,
    // A half the door refused because its signed claims contradict
    // our record is a disagreement too, though it is never held as a sibling.
    mismatch:
      siblings.filter((sibling) => siblingGateState(sibling).kind === 'contradicted').length +
      (row.claims_refused ?? 0),
    contradicted: row.verdicts?.tally?.contradicted ?? 0
  }
}

// ---------------------------------------------------------------------------
// Alarm -- the most-recent negative signal, surfaced even collapsed.
// ---------------------------------------------------------------------------

export type AlarmSignal = { present: boolean; text: string; tone: 'bad' | 'warn' }

/** `resolveTimestamp` is an optional local-ledger lookup (the Ledger page
 *  already has `recordsById` from the raw capsule ledger) so a contradiction
 *  date can be shown when it's genuinely recoverable -- never fabricated
 *  when it isn't. */
export function alarmSignal(row: PaneBRow, resolveTimestamp?: (capsuleId: string) => string | null): AlarmSignal {
  const verdicts = row.verdicts
  if (row.referee_verdicts && adjudicationSummary(row).contradicted > 0) {
    return { present: true, text: 'A referee found their answer contradicted', tone: 'bad' }
  }
  if (!row.referee_verdicts && verdicts?.state === STATE_CONTRADICTED) {
    const capsuleId = verdicts.adjudication_capsule_id
    const when = capsuleId ? (resolveTimestamp?.(capsuleId) ?? null) : null
    return { present: true, text: when ? `Contradiction found ${when}` : 'Contradiction found', tone: 'bad' }
  }
  if (row.history?.state === STATE_FAILED) {
    return { present: true, text: 'Chain verification failed', tone: 'bad' }
  }
  if (row.history?.state === STATE_REFUSED || row.served?.state === STATE_REFUSED) {
    return { present: true, text: 'Peer refused a request', tone: 'warn' }
  }
  return { present: false, text: '', tone: 'warn' }
}

/** When the contradicting verdict was sealed, if the local ledger holds it. */
function adjudicationDate(row: PaneBRow, resolveTimestamp?: (capsuleId: string) => string | null): string | null {
  const capsuleId = row.verdicts?.adjudication_capsule_id
  return capsuleId ? (resolveTimestamp?.(capsuleId) ?? null) : null
}

export type PeerAttentionKey = keyof typeof PEER_ATTENTION
export type PeerAttentionItem = { key: PeerAttentionKey; label: string; tooltip: string; tone: 'bad' | 'warn' }

/** The specific things on a peer row that need a look, each counted from the
 *  payload -- never a number the payload doesn't carry. `disagreements` are the
 *  exchanges the ONE gate reads as CONTRADICTED; `differingAnswers` the sealed
 *  comparisons that found a contradiction. A failed log check and a refusal are
 *  states with no count, so they are named, not numbered. */
export function peerAttention(
  row: PaneBRow,
  resolveTimestamp?: (capsuleId: string) => string | null
): PeerAttentionItem[] {
  const items: PeerAttentionItem[] = []
  const disagreements = matchTally(row).mismatch
  if (disagreements > 0) {
    items.push({
      key: 'disagreements',
      label: PEER_ATTENTION.disagreements.label(disagreements),
      tooltip: PEER_ATTENTION.disagreements.tooltip(disagreements),
      tone: 'bad'
    })
  }
  const differing = row.referee_verdicts
    ? adjudicationSummary(row).contradicted
    : row.verdicts?.state === STATE_CONTRADICTED
      ? (row.verdicts.tally?.contradicted ?? 0)
      : 0
  if (differing > 0) {
    items.push({
      key: 'differingAnswers',
      label: PEER_ATTENTION.differingAnswers.label(differing),
      tooltip: PEER_ATTENTION.differingAnswers.tooltip(differing, adjudicationDate(row, resolveTimestamp)),
      tone: 'bad'
    })
  }
  if (row.history?.state === STATE_FAILED) {
    items.push({
      key: 'logFailed',
      label: PEER_ATTENTION.logFailed.label(),
      tooltip: PEER_ATTENTION.logFailed.tooltip(),
      tone: 'bad'
    })
  }
  if (row.history?.state === STATE_REFUSED || row.served?.state === STATE_REFUSED) {
    items.push({
      key: 'refused',
      label: PEER_ATTENTION.refused.label(),
      tooltip: PEER_ATTENTION.refused.tooltip(),
      tone: 'warn'
    })
  }
  return items
}

// ---------------------------------------------------------------------------
// Sort -- closest-first, alarms float to top. Never a trust ordering.
// ---------------------------------------------------------------------------

/** Rows with something to look at -- a disagreement, a dispute that found a
 *  difference, a log that didn't check out, a refusal -- come first (UX §2:
 *  "should I stop dealing with anyone?"). Never a trust ordering. */
export function peerSortKey(row: PaneBRow, latencyMs: number | null): readonly [number, number] {
  const alarmRank = alarmSignal(row).present || peerAttention(row).length > 0 ? 0 : 1
  const latency = latencyMs ?? Number.POSITIVE_INFINITY
  return [alarmRank, latency] as const
}

export function sortPeerRows<T>(rows: readonly T[], keyOf: (row: T) => readonly [number, number]): T[] {
  return [...rows].sort((a, b) => {
    const [aRank, aLatency] = keyOf(a)
    const [bRank, bLatency] = keyOf(b)
    return aRank - bRank || aLatency - bLatency
  })
}

// ---------------------------------------------------------------------------
// Witness -- no pane exposes a peer-scoped witness registration count today
// (`history.mine_for_reference.witnessed` is THIS node's OWN chain, carried
// for reference only, never the peer's -- see `PaneBHistoryCell`), so this
// states the absence honestly instead of borrowing that field.
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// Last dealt with -- the date of a row's latest exchange (UX §2), rendered by
// `periodRangeText`. `—` when there is no exchange history (the "advertised
// but unused" group).
// ---------------------------------------------------------------------------

function periodDateParts(iso: string): { day: number; month: string; year: number } {
  const parsed = new Date(iso)
  return {
    day: parsed.getUTCDate(),
    month: parsed.toLocaleString('en-US', { month: 'short', timeZone: 'UTC' }),
    year: parsed.getUTCFullYear()
  }
}

export function periodRangeText(firstSeen: string | null, lastSeen: string | null): string {
  if (!firstSeen || !lastSeen) return '—'
  const first = periodDateParts(firstSeen)
  const last = periodDateParts(lastSeen)
  if (first.year === last.year && first.month === last.month) {
    return first.day === last.day ? `${first.day} ${first.month}` : `${first.day}–${last.day} ${first.month}`
  }
  if (first.year === last.year) {
    return `${first.day} ${first.month} – ${last.day} ${last.month}`
  }
  return `${first.day} ${first.month} ${first.year} – ${last.day} ${last.month} ${last.year}`
}

// ---------------------------------------------------------------------------
// Unified row view -- one shape for both row groups ("dealt with" rows
// carry the full Pane B row; "advertised but unused" rows have no exchange
// history at all, so every accountability column degrades to the honest
// "—" placeholder rather than a fabricated zero-of-zero).
//
// Accountability-only: no online status,
// latency, or route-to-chat field here (Network's job) -- see
// `PeerTableRow.tsx`.
// ---------------------------------------------------------------------------

export type PeerTableRowView = {
  key: string
  displayId: string
  /** The row's alias evidence, one line (`peerAliasLine`): the other id
   *  spaces this ONE peer is known by -- never rendered as extra peers.
   *  `null` when the row carries no identity evidence. */
  aliasLine: string | null
  /** One honesty caveat under the identity, stated once (chooser-v2 §3
   *  discipline carried over): empty for a dealt-with peer (the legend says it once),
   *  "no exchanges yet" for one only advertised. */
  exchangeCount: number
  /** Exchanges with this peer that failed; counted apart from `exchangeCount`. */
  failedCount: number
  period: string
  /** The "Needs a look" filter: only what the row itself shows -- a caught swap, a
   *  differing record, a failed log check or a refusal. */
  needsALook: boolean
  /** What needs a look, each named and counted -- replaces the old generic
   *  ⚠ chip on the face (UX §8). Empty when nothing does. */
  attention: PeerAttentionItem[]
  /** Payments with this peer, counted (`peerSettlementText`); `null` when
   *  there is no paid exchange on record. */
  payments: string | null
  /** The three columns the table and the drawer share (`peerFacts`). */
  facts: PeerFacts
  row: PaneBRow | null
}

// ---------------------------------------------------------------------------
// The three ways a stranger could cheat, per peer: the Peers table's three
// badge columns and the drawer's three rows read these. Every figure is one the
// page already holds (pane B for the peer, pane C for the pairs); one with no
// source here reads "not checked", never a guess.
// ---------------------------------------------------------------------------

export type PeerBadgeTone = 'good' | 'warn' | 'bad' | 'muted'
export type PeerBadge = { text: string; tone: PeerBadgeTone }

export type PeerSwappedFacts = PeerBadge & {
  /** Pairs a referee this node asked ruled on, naming a ruling on the answers
   *  (an inconclusive one counts; a not-comparable one is no check at all). */
  checked: number
  /** Of those, the pairs where the referee ruled THIS peer's answer wrong. */
  caught: number
  /** "1 caught · 3 checked", or "not checked" with none asked. */
  tally: string
  /** The other machine the same request also went to, when known. */
  otherNode: string | null
  /** The referee that ruled on the caught pair, when there is one. */
  referee: string | null
}

export type PeerFacts = {
  /** The peer served at least one of your sealed exchanges. */
  rewrote: PeerBadge
  /** Their signed records that name the same request, answer and model as yours. */
  leftOut: PeerBadge & { matched: number; total: number; differ: number }
  swapped: PeerSwappedFacts
  /** A referee this node asked ruled on a pair as this peer. */
  actedAsReferee: boolean
}

/** Every id this peer is known by on this page: pane C names a counterparty by
 *  the same display id, a verdict names a node by node id. */
function peerIds(row: PaneBRow, displayId: string): ReadonlySet<string> {
  const { signingKeyId, endpointId, nodeId } = peerIdentityAliases(row)
  return new Set(
    [displayId, row.peer_id, row.node?.peer_id, signingKeyId, endpointId, nodeId].filter(
      (id): id is string => typeof id === 'string' && id.length > 0
    )
  )
}

/** Reads the same thing `askedVerdicts` (attack-cards.ts) reads: only a verdict
 *  this node asked for and holds as a sealed record (`twin.referee_row`
 *  adjudicated on this node's own rows). A verdict another node delivered, and
 *  any mismatch inferred from the two answers, never count. */
export function peerSwappedFacts(
  ids: ReadonlySet<string>,
  exchangeRows: readonly PaneCRow[]
): PeerSwappedFacts {
  const pairs = new Map<string, { wire: string | null; otherKey: string | null; referee: string | null }>()
  for (const row of exchangeRows) {
    const bracket = row.twin?.bracket_id
    if (!bracket || !row.counterparty || !ids.has(row.counterparty)) continue
    const recorded = row.twin?.referee_row
    const asked = recorded?.state === 'adjudicated'
    const prior = pairs.get(bracket)
    if (prior && (prior.wire !== null || !asked)) continue
    pairs.set(bracket, {
      wire: asked ? recorded.verdict : null,
      otherKey: row.twin?.other_row ?? null,
      referee: asked ? recorded.referee : null
    })
  }
  let checked = 0
  let caught = 0
  let cleared = 0
  let otherNode: string | null = null
  let referee: string | null = null
  for (const pair of pairs.values()) {
    const verdict = parseVerdict(pair.wire)
    if (!verdict || verdict.kind === 'not_comparable') continue
    checked += 1
    if (verdict.kind === 'corroborated') cleared += 1
    else if (verdict.kind === 'contradicted') {
      const other = exchangeRows.find((r) => r.exchange_key === pair.otherKey)?.counterparty ?? null
      if (ids.has(verdict.party)) {
        caught += 1
        otherNode = other ?? otherNode
        referee = pair.referee ?? referee
      } else if (other !== null && verdict.party === other) {
        // The referee ruled the OTHER machine's answer wrong: this peer is cleared.
        cleared += 1
      }
      // A party that is neither this peer nor the other machine by any id this
      // page holds is checked but not attributed: neither caught nor cleared.
    }
  }
  const badge: PeerBadge =
    caught > 0
      ? { text: 'Contradicted by referee', tone: 'bad' }
      : cleared > 0
        ? { text: 'Corroborated by referee', tone: 'good' }
        : checked > 0
          ? { text: 'Checked', tone: 'muted' }
          : { text: 'Not tested', tone: 'muted' }
  return {
    ...badge,
    checked,
    caught,
    tally: checked === 0 ? 'not checked' : `${caught} caught · ${checked} checked`,
    otherNode,
    referee
  }
}

export function peerFacts(row: PaneBRow, exchangeRows: readonly PaneCRow[] = []): PeerFacts {
  const displayId = peerDisplayId(row) ?? ''
  const ids = peerIds(row, displayId)
  const total = row.exchange_count ?? 0
  const matched = confirmedByOtherSide(row).confirmed
  const differ = matchTally(row).mismatch
  const refereed = exchangeRows.some((exchange) => {
    const recorded = exchange.twin?.referee_row
    // Only a ruling this node asked for and holds; `twin.referee_node_id` also
    // rides on verdicts other nodes delivered.
    return recorded?.state === 'adjudicated' && ids.has(recorded.referee)
  })
  return {
    rewrote: total > 0 ? { text: 'Sealed', tone: 'good' } : { text: 'not checked', tone: 'muted' },
    leftOut:
      total === 0
        ? { text: 'not checked', tone: 'muted', matched, total, differ }
        : differ > 0
          ? { text: `${differ} of ${total} differ`, tone: 'bad', matched, total, differ }
          : { text: `${matched}/${total} matched`, tone: matched === total ? 'good' : 'warn', matched, total, differ },
    swapped: peerSwappedFacts(ids, exchangeRows),
    actedAsReferee: refereed
  }
}

/** The two attention items the Peers row still draws; a disagreement and a
 *  differing answer are the Left-something-out and Swapped columns. */
export function isShownAttention(item: PeerAttentionItem): boolean {
  return item.key === 'logFailed' || item.key === 'refused'
}

export function dealtWithRowView(
  row: PaneBRow,
  resolveTimestamp?: (capsuleId: string) => string | null,
  /** The Exchanges rows (pane C), for this peer's twin pairs. */
  exchangeRows: readonly PaneCRow[] = [],
  /** The key announced for an unlinked peer's node (`unlinkedNodeId`). */
  announcedKeyId: string | null = null
): PeerTableRowView {
  // `peerDisplayId` returns `null` for a row with no counterparty identity
  // at all (see its own doc comment) -- callers filter those out before
  // reaching here, but this fallback keeps the view honest, never `null`,
  // if ever called directly with one.
  const displayId = peerDisplayId(row) ?? 'other side not recorded'
  const facts = peerFacts(row, exchangeRows)
  const attention = peerAttention(row, resolveTimestamp)
  return {
    key: row.peer_id ?? displayId,
    displayId,
    aliasLine: peerAliasLine(row, announcedKeyId),
    // UX §2: "self-reported" is true of every row, so it lives once in the
    // table legend, not on each row.
    exchangeCount: row.exchange_count ?? 0,
    failedCount: row.role?.failed_count ?? 0,
    period: periodRangeText(row.last_seen, row.last_seen),
    needsALook: facts.swapped.caught > 0 || facts.leftOut.differ > 0 || attention.some(isShownAttention),
    attention,
    payments: peerSettlementText(row.settlement),
    facts,
    row
  }
}

// ---------------------------------------------------------------------------
// Column keys -- shared between `PeerTableRow` and `LedgerPeersTable`'s
// Columns toggle. Lives here (a non-component module) rather than in either
// component file so exporting it never trips the fast-refresh
// only-export-components lint rule.
// ---------------------------------------------------------------------------

export type PeerTableColumnKey = 'exchanges' | 'rewrote' | 'leftOut' | 'swapped' | 'period'

export const ALL_PEER_TABLE_COLUMNS: ReadonlySet<PeerTableColumnKey> = new Set<PeerTableColumnKey>([
  'exchanges',
  'rewrote',
  'leftOut',
  'swapped',
  'period'
])

// The per-column (i) hover copy -- what the column means and what evidence
// backs it, moved off the face and behind the glyph. Each states the evidence,
// never a standing or score reading (the three-sharer-answers framing: what it
// is, what backs it, what it does NOT establish). The `confirmed` line is the
// task's blessed wording verbatim.
export const PEER_COLUMN_INFO: Record<PeerTableColumnKey, string> = PEER_COLUMN_TOOLTIPS
