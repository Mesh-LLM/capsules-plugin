// The Evidence tab's hover copy, in one place (
// UX review §8). One tooltip per chip TYPE, shared by every instance of it, so
// the census test (`tooltip-census.test.tsx`) can check each one: present,
// one plain sentence or two, no retired phrase, and -- outside Dig (the checks
// panel) -- none of the engineer's words ("half", "capsule id", "leaves",
// "recomputed"). Say what a thing is, never what it isn't: a banned word stays
// off the screen even to deny it.
//
// The Peers column and Integrity tile NAMES are unchanged here; their renames
// land with the plain-language pass. Every sentence below reads
// correctly under either name.

/** Hero buttons (the InfoBanner's status row). */
export const HERO_TOOLTIPS = {
  yourRecords: 'The records this node keeps, sealed and checkpointed. Open to see where they are and what you share.',
  // The storage-posture pills,
  // mirroring Logs. Facts, not features.
  // Shown only when every switch under What you share is off.
  localOnly: 'Nothing is sent from this machine: every switch under What you share is off.',
  digestsOnly: 'Each record holds a fingerprint of the prompt and the answer, never the words themselves.',
  promptsKept: 'The words of your prompts and answers are stored on this machine only, apart from the records.',
  promptsNotKept: 'No prompt or answer text is stored on this machine. The records hold fingerprints only.',
  promptsUnknown: 'This view can’t tell whether prompt and answer text is stored on this machine.'
} as const

/** p2 item 3: the owner-link fact, worded once for Integrity's step 2 and
 *  the checks panel's binding fact. */
export const OWNER_LINKED_PHRASE = 'linked to your owner account (self-asserted)'
export const OWNER_NOT_LINKED_PHRASE = 'not linked to an owner'

/** p2 item 5: why an action is disabled -- said on hover, never a silent grey. */
export const SAMPLE_DATA_UNAVAILABLE = 'Not available on sample data.'

/** The header's one line: 20 words, no icons (Steven's word budget, Sherlock2's wording). */
export const HERO_DESCRIPTION =
  'Every answer a stranger gave you is sealed and signed. Three ways they could cheat you, and whether any did.'

/** Peers table column headers. */
export const PEER_COLUMN_TOOLTIPS = {
  exchanges: 'Distinct exchanges with this peer. Your record and theirs of the same exchange count once.',
  rewrote:
    'Whether the records you hold of this peer are sealed: signed when the exchange happened, so a later edit would show.',
  leftOut:
    'How many of their signed records name the same request, answer and model as yours, out of all your exchanges with them. A record that differs is counted as differing.',
  swapped:
    'What a referee you asked ruled about this peer’s answers, out of how many were checked. Not tested means you asked no referee.',
  period: 'The date of your latest exchange with this peer.'
} as const

/** The sentence above the Peers table: a count, then why the names are not evidence. */
export function peersHeaderSentence(count: number): string {
  return `${count} ${count === 1 ? 'peer' : 'peers'} on the record. Names are self-reported; only signed records count.`
}

/** The line under the Peers table. */
export const PEERS_FOOTER = 'Nothing here changes routing. Records stay on this node and are never sent to anyone.'

/** The peer drawer's three rows and its footer. */
export const PEER_DRAWER = {
  rewroteTitle: 'Rewrote the record',
  leftOutTitle: 'Left something out',
  swappedTitle: 'Swapped the model',
  rewroteSealed:
    'Your record is signed and sealed when it happened, so a later edit would show.',
  rewroteTheirs: 'Theirs is signed with their key. Neither side can edit it quietly.',
  leftOutMatched: 'Their signed record names the same request, answer and model as yours.',
  leftOutNone: 'No signed record from them has been checked against yours yet.',
  leftOutDiffer: 'Their signed record differs from yours on the request, the answer or the model.',
  historyNotCompared: 'You haven’t compared full histories yet.',
  historyChecked: 'Their full history was checked on this machine.',
  historyFailed: 'Their full history was fetched and did not check out.',
  historyRefused: 'They refused to show their full history.',
  swappedNone: 'You haven’t asked a referee to compare this peer’s answers, so nothing is checked.',
  swappedSealed: 'The ruling is a record sealed on this node.',
  routing: 'Routing: unchanged. This page shows records, nothing more.',
  openExchanges: 'Open in Exchanges',
  askHistory: 'Ask a peer for their history',
  openVerdict: 'Open the verdict'
} as const

export const PEER_NEEDS_A_LOOK_LABEL = 'Needs a look'

/** Peer attention badges -- the specific thing, counted, replacing the old
 *  generic ⚠ alarm chip. Each is one sentence naming exactly that. */
export const PEER_ATTENTION = {
  disagreements: {
    label: (n: number) => `${n} disagreement${n === 1 ? '' : 's'}`,
    tooltip: (n: number) => `${n} exchange${n === 1 ? '' : 's'} where your record and theirs disagree.`
  },
  differingAnswers: {
    label: (n: number) => `${n} differing answer${n === 1 ? '' : 's'}`,
    tooltip: (n: number, when?: string | null) =>
      `${n === 1 ? '1 comparison your node sealed' : `${n} comparisons your node sealed`} found this peer’s answer differed from another machine’s.${
        when ? ` Latest: ${when}.` : ''
      }`
  },
  logFailed: {
    label: () => 'log didn’t check out',
    tooltip: () => 'Your node fetched their log and it failed its checks on this machine.'
  },
  refused: {
    label: () => 'refused a request',
    tooltip: () => 'They declined a request and signed the refusal.'
  }
} as const

/** The row's state badge: the (i) beside Confirmed / Disagree / Waiting for
 *  theirs and the rest. */
export const ROW_STATE_TOOLTIPS = {
  closed:
    'They sent their own signed record of this exchange, from the node that served you, and it checks out on this machine. It names the same request, answer and model weights as yours.',
  contradicted:
    'You both have signed records of this exchange and they disagree: the request, the answer, the model or who served it differs, or their record doesn’t match its own id. Use Compare to see where.',
  open_refused:
    'They declined to share their record and signed the refusal. The refusal is the evidence; nothing of theirs is compared.',
  open_absent:
    'They say they have no record of this exchange. That is their statement; there is nothing of theirs to check.',
  open_asked: 'You asked for their record and no verified reply has arrived yet.',
  open_not_held:
    'Their record hasn’t arrived, or what arrived couldn’t be confirmed as theirs from the node that served you. It arrives on its own only if their node sends records (on by default, unless its operator turned it off); otherwise, ask for it on this row.',
  open_not_given:
    'Their record hasn’t arrived, and nothing they sent names it by its id. It arrives on its own only if their node sends records (on by default, unless its operator turned it off); otherwise, ask for it on this row.',
  open_not_asked:
    'Their record hasn’t arrived. It arrives on its own only if their node sends records (on by default, unless its operator turned it off); otherwise, ask for it on this row.'
} as const

/** The per-property cells a CLOSED row shows, each with its own (i). */
export const CLOSED_CELL_TOOLTIPS = {
  their_id: 'The id of their record; it’s a fingerprint of the record itself.',
  signature: 'Signed with this peer’s signing key, as this node knows it.',
  request: 'The same request as in your record.',
  response: 'The same answer as in your record.'
} as const


/** The chip strip, per result: what a ✓, ✗ or – on each chip means (and,
 *  on the checkpoint chip, ◐: a checkpoint covers it, not checked here), and
 *  the check behind it. The words-match and signed chips are checked on this
 *  machine (recompute-identity.ts); in-a-checkpoint is the node's count, not
 *  a checked proof; witnessed is read, not checked here. */
export const ENTRY_CHIP_RESULT_TOOLTIPS = {
  content: {
    '✓': 'Your record’s fingerprint, checked on this machine, still equals the id it was sealed with, so nothing in it has changed.',
    '✗': 'Your record no longer matches its id, so it changed after it was sealed. Save the evidence file and check this node’s storage.',
    '–': 'Not checked yet: this page hasn’t loaded your record.'
  },
  sig: {
    '✓': 'The signature on your record checks against this node’s key, on this machine.',
    '✗': 'The signature on your record doesn’t check against this node’s key.',
    '–': 'Not checked: the signed copy or this node’s key isn’t available to this page.'
  },
  inclusion: {
    '✓': 'A checkpoint this node signed covers this record, by the node’s own count. This page doesn’t check that coverage itself.',
    '✗': 'The node reports that no checkpoint covers this record.',
    '–': 'No checkpoint covers this record yet; the next checkpoint the node makes will.',
    '◐': 'A checkpoint on this node covers this record, as Integrity counts. This row hasn’t checked that for itself yet.'
  },
  registered: {
    '✓': 'A witness you don’t run holds a checkpoint covering this record. The witness’s receipt isn’t checked on this page.',
    '✗': 'The node reports that no witness holds a checkpoint covering this record.',
    '–': 'No witness you don’t run holds a checkpoint covering this record. Not checked here.'
  },
  theirs: {
    '✓': 'Confirmed: their own signed record, from the node that served you, names the same request, answer and model weights as yours.',
    '✗': 'Their signed record disagrees with yours, or doesn’t match its own id. The state on the right says more.',
    '–': 'No confirmed record from them yet; the state on the right says why.'
  }
} as const

/** The LOCAL badge's (i): a served exchange with no other side recorded. */
export const LOCAL_ONLY_TOOLTIP =
  'This node only. This node served the request and no other side is recorded for it, so there is no record of theirs to wait for. It is not counted as open.'

/** The FAILED badge's (i): the exchange did not complete. */
export const FAILED_TOOLTIP =
  'The exchange failed, so there is no completed exchange for the other side to have a record of. It is not counted as open.'

/** The OPEN badge's (i) on a row served for pay whose payer is not recorded:
 *  it has no ask target, so it stays open unless the payer's record arrives. */
export const SERVED_FOR_PAY_NO_PAYER_TOOLTIP =
  'Open, and it may stay open: another node paid for this exchange, but this node didn’t record which one, so it can’t ask for their record. It closes only if the payer sends theirs.'

/** The Exchanges tab's opening line: what a row is, and what Confirmed
 *  means (Steven's acceptance for the plain-verdict pass; copy reviewed). */
export const EXCHANGES_INTRO =
  'Each exchange leaves two signed records, one per side. Confirmed means both say the same thing.'

/** Each row's plain verdict, on its face; the longer sentences behind its
 *  (i). A Disagree row keeps its own wording (`rightCellText`). */
export const ROW_VERDICT = {
  confirmed: (peer: string) => `✓ You and ${peer} recorded the same exchange`,
  waiting: 'Waiting for their record',
  declined: 'They declined'
} as const
/** Who the confirmed verdict names when no record names the other node. */
export const ROW_VERDICT_UNNAMED_PEER = 'the other side'

/** A confirmed row whose held record of theirs came by ask (`theirs.via ===
 *  "ask"`), said behind the verdict's (i) (Sherlock2's acceptance). */
export const SAVED_BECAUSE_YOU_ASKED = 'Saved on this node because you asked them for it.'

/** A row confirmed from a record an ask brought that the plugin couldn't
 *  save (its id isn't in the tool's `held`), said behind the verdict's (i)
 *  in place of `SAVED_BECAUSE_YOU_ASKED`. */
export const CONFIRMED_NOT_KEPT =
  'Confirmed from the record you asked for, but this node couldn’t save it, so a reload won’t keep it.'

/** The three steps under each row, in order. */
export const ROW_STEP_LABELS = {
  sealed: 'Sealed',
  checkpoint: 'In a checkpoint',
  confirmed: 'Confirmed by them'
} as const

/** A confirmed exchange whose own record fails its checks: said on the row,
 *  so a Confirmed badge never sits beside a failed check unexplained. */
export const OWN_RECORD_FAILS_WARNING =
  'Your own copy of this record fails its checks, so neither side can rely on it, whatever the badge says.'

/** The side-by-side check (the twin bracket): its hovers. The answer
 *  comparison is this node's plugin comparing the two sealed answer
 *  fingerprints (evidence_panes.rs attach_twins); a verdict is a referee's
 *  signed record, read here, its signature checked by the plugin. */
export const TWIN_TOOLTIPS = {
  header: 'Your node sent the same request to two machines and kept both answers, so they can be compared.',
  same: 'The two machines’ answers have the same fingerprint, compared by this node. That is not a verdict.',
  different: 'The two machines’ answers have different fingerprints, compared by this node. That alone doesn’t say which is wrong.',
  not_compared: 'Not compared yet: one of the two answers’ fingerprints hasn’t reached this node.',
  verdict: 'A referee’s verdict on this pair, as this node recorded it. Open it to see whether the referee’s signature checks here.',
  parameters: 'The settings both machines were asked to use; a difference here can explain a different answer.',
  compare: 'Show the two answers side by side. This page doesn’t judge them.',
  save: 'Download both records of this side-by-side check as a file.'
} as const

/** The side-by-side check's verdict badge, per ruling the referee sealed. */
export const TWIN_VERDICT_TOOLTIPS = {
  corroborated: 'A referee’s verdict, as this node recorded it: the two answers agree. Open it to see whether the referee’s signature checks here.',
  contradicted: 'A referee’s verdict, as this node recorded it: one answer is wrong. Open it to see whether the referee’s signature checks here.',
  inconclusive: 'A referee compared the two answers and couldn’t decide between them. That is not a disagreement.',
  not_comparable: 'The two answers were sampled, so a referee can’t compare them. This is never a disagreement.'
} as const

/** The TWIN bracket's `not adjudicated` badge. */
export const TWIN_NO_VERDICT_TOOLTIP =
  'The same request went to two machines and both answers are recorded. A referee is asked only when they differ at temperature 0 on the same model and weights, and until one signs a verdict nothing counts against either machine.'

/** The one wording for "no witness holds your checkpoints": the hero, the
 *  Your records panel and the Integrity tile all say this. */
export const WITNESS_OFF = 'witness off — your choice'

/** Integrity tiles. */
export const INTEGRITY_TILE_TOOLTIPS = {
  sealed:
    'Records this node sealed into its log, not counting padding. Sealed means a record can’t change unnoticed; it doesn’t make the contents true.',
  confirmedByOtherSide: 'Exchanges saved on this node that the other side confirmed with their own signed record, checked on this machine.',
  contradicted:
    'Exchanges where your record and theirs disagree: a different request, answer, model or server, or their record not matching its own id.'
} as const

/** The Exchanges header's one setup button: it opens Integrity and does
 *  nothing else, so the hover says exactly that. */
export const SETUP_STEPS_LABEL = 'See the setup steps'
export const SETUP_STEPS_TOOLTIP =
  'Opens Integrity, which lists how to get the other side’s record and how to have a witness hold your checkpoints.'

/** Integrity: Continuity, and the evidence file download. */
export const CONTINUITY_TOOLTIP =
  'Whether each checkpoint builds on the one before, so a rewrite would show. This page reads the node’s status and doesn’t check it.'
export const SAVE_EVIDENCE_FILE_TOOLTIP =
  'Download this node’s records and checkpoint facts as one file that anyone can check without this app.'

/** Integrity's chain coverage strip. */
export const CHAIN_STRIP_TOOLTIP =
  'Shaded: records sealed into a checkpoint. Unshaded: records sealed since the last checkpoint.'

/** The checks panel's chips (Dig), one per property. Hover for the meaning;
 *  a click still opens the four-part explanation (v3 §4). Dig may use the
 *  exact terms, but each hover is still one plain sentence. */
export const CHECK_CHIP_TOOLTIPS: Record<string, string> = {
  content_binding: 'Whether the record’s contents still match its id.',
  producer_signature: 'Whether the record is signed with its node’s signing key.',
  task_binding: 'Whether the record is tied to the request it answers.',
  local_inclusion: 'Whether a checkpoint on the node that sealed it covers this record.',
  checkpoint_signature: 'Whether that checkpoint is signed by the node that made it.',
  external_registration: 'Whether a witness that node doesn’t run holds the checkpoint.',
  continuity: 'Whether that checkpoint binds to the one before it.',
  outcome_corroboration: 'Whether the other side’s own record confirms what happened.',
  'identity_authority:binding': 'Whether the signing key is bound to an owner identity.',
  'identity_authority:authority': 'Whether that owner identity is bound to a person.'
}

export function checkChipTooltipKey(propertyKey: string, factKey?: 'binding' | 'authority'): string {
  return factKey ? `${propertyKey}:${factKey}` : propertyKey
}

/** A split request's stage strip (docs/DESIGN-split-stage-records.md §7.2).
 *  Face copy: plain words, and `agree` never claims more than the records do.
 *  Which node ran which stage is the coordinator's word: a stage record's key
 *  is not linked to a node on this page, so the copy says so. */
export const SPLIT_TOOLTIPS = {
  stageCell:
    'The coordinator says which node ran each stage. A tick means that stage’s record matches what the coordinator assigned it.',
  handoffs:
    'The records at both ends of each hand-off name the same data. It says the two records agree, not which node signed them, that the nodes are independent, or that any layer was computed correctly.',
  throughSplit:
    'Nodes the coordinator says ran part of a request you sent it. You never dealt with them directly.'
} as const

/** The stage strip: one hover per cell state and per hand-off state. */
export const STAGE_CELL_TOOLTIPS = {
  coordinator_slice: 'The part of the request the coordinator ran itself.',
  ok: 'This stage’s record matches what the coordinator assigned it.',
  disagrees: 'This stage’s record doesn’t match what the coordinator assigned it.',
  not_received: 'No record from this stage reached you.',
  not_requested: 'This stage wasn’t part of the run.',
  conflict: 'Two different records claim this stage; one of them is wrong.',
  rejected: 'A record here is broken or isn’t a valid record of this stage, so it can’t be read.'
} as const

export const HANDOFF_TOOLTIPS = {
  agree: 'The records at both ends of this hand-off name the same data.',
  gap: 'One end of this hand-off has no record.',
  break: 'The two ends of this hand-off name different data.',
  malformed: 'A record at this hand-off is broken and can’t be read.'
} as const

/** The drill's "Referee verdicts about them" section. Plain words first, then
 *  the check actually run: `verdict_counts.rs` counts only the
 *  adjudication_received / adjudication_issued records on this node's chain,
 *  which the plugin seals after the door verifies the referee's signature
 *  (the plugin's `referee::hold::verdict_facts`). */
export const REFEREE_VERDICTS_ABOUT_THEM = {
  sectionTitle: 'Referee verdicts about them',
  explainer:
    'How often a referee, re-answering a request both this peer and another peer served, agreed or disagreed with this peer. Counted from verdicts this node asked a referee for, as this node recorded them: its door records one only after checking the referee’s signature against the key that referee announced. A verdict nobody here asked for isn’t counted, and one referee counts once per pair of answers. Open a record to see whether the referee’s signature checks here. The four counts stay on this node, are never sent to anyone, and are never combined into one number.',
  notShown: 'Not shown: this plugin version doesn’t count referee verdicts.',
  bucketTooltip: {
    corroborated: 'The referee’s answer matched this peer’s answer.',
    contradicted: 'The referee’s answer matched the other peer’s answer, not this one’s.',
    inconclusive: 'The referee’s answer matched neither answer, so it named no one.',
    not_comparable: 'The two answers were sampled, not greedy, so they can’t be compared and the referee named no one.'
  }
} as const

/** The drill's routing section. Stopping routing to a peer needs the host's
 *  local block list, which this page does not reach, so the page says so
 *  instead of offering a button that could not act. */
/** The row's "see in Logs": opening Logs at one exchange needs a host hook
 *  this page doesn't have, so the row says so instead of a dead link. */
export const SEE_IN_LOGS_NOT_ON_THIS_PAGE = 'this page can’t open Logs at this exchange yet'

export const ROUTING_NOT_ON_THIS_PAGE = {
  sectionTitle: 'Routing to this peer',
  text: 'This page can’t stop routing to a peer. It shows your records and changes nothing about routing.'
} as const

/** Payments on an exchange row: the `paid` chip and its settlement state.
 *  Only this node's records exist, so every sentence is about your side. */
export const SETTLEMENT_TERMS_TOOLTIP = 'You accepted the terms for this exchange, and no invoice was recorded for it.'

export const SETTLEMENT_PAID_TOOLTIP =
  'This exchange was invoiced, and this node recorded each payment step it saw. The wallet keeps the money; these are the records.'

export const SETTLEMENT_STATE_TOOLTIPS = {
  settled:
    'Every invoice you saw for this exchange was reported paid by your wallet, under the same payment reference.',
  settled_without_reference:
    'Your wallet reported each invoice’s part of this exchange paid, but at least one report carried no payment reference to match on.',
  no_settlement_seen: 'At least one invoice has no payment reported by your wallet. Your records alone can’t say why.',
  outcome_not_reported:
    'An invoice was issued, your wallet reported no payment for it, and no final amount was recorded. The host reports no outcome here: the payment may be uncertain (its result unknown after a lost wallet reply), it may have failed, or the exchange was interrupted or is still running. These records can’t say which.',
  terms_only: 'You accepted the terms, and no invoice was recorded.',
  unmatched_settlement: 'Your wallet reported a payment that no invoice for this exchange names.'
} as const

/** An exchange this node served for pay: its own records as the provider. */
export const SETTLEMENT_PROVIDER_PAID_TOOLTIP =
  'You served this exchange for pay. These are the payment steps this node recorded as the provider; the requester’s own record isn’t shared with this node.'

export const SETTLEMENT_PROVIDER_STATE_TOOLTIPS = {
  settled: 'Every invoice you issued for this exchange was reported received by your wallet.',
  outcome_not_reported:
    'You issued an invoice and your wallet reported no payment for it. The host reports no outcome here: the payment may be uncertain, it may have failed, or the exchange was interrupted or is still running. These records can’t say which.',
  terms_only: 'Terms were accepted, and no invoice was recorded.',
  unmatched_settlement: 'Your wallet reported a payment that no invoice of yours for this exchange names.'
} as const

/** Said once beside the payment counts: what leaves no payment record at all. */
export const SETTLEMENT_REFUSED_NOTE =
  'A paid request refused before any payment (for example, a payment protocol version the other node doesn’t speak) leaves no payment records here: it shows as an exchange with its error and no payment chip. The host doesn’t report the reason.'

export const SETTLEMENT_PROVIDER_BOOK_TOOLTIP =
  'The provider’s own record of this payment isn’t shared with this node, so only your side is shown.'

/** Who stated each recorded payment value. */
export const SETTLEMENT_SOURCE_TOOLTIPS = {
  payer_asserted: 'Recorded by this node as what it agreed to or accounted.',
  provider_asserted: 'What the provider stated, as it reached this node.',
  wallet_reported: 'What your wallet reported.'
} as const

/** Who stated each value on this node's own book as the provider. */
export const SETTLEMENT_PROVIDER_SOURCE_TOOLTIPS = {
  payer_asserted: 'What the payer stated, as it reached this node.',
  provider_asserted: 'Recorded by this node, as the provider, as what it stated or delivered.',
  wallet_reported: 'What your wallet reported receiving.'
} as const

/** The Peers row's payments line. */
export const PEER_PAYMENTS_TOOLTIP =
  'Counts of your paid exchanges with this peer, from your own records. The provider’s own book isn’t shared with this node.'

/** Integrity's Close card: agreed periods, then the counts that are in none. */
export const CLOSE_CARD_TOOLTIP =
  'A period both sides have closed: one side seals a Close with its counts for the period, and the other side acknowledges it. None yet on this node.'

export const CLOSE_CARD_COUNTS_TOOLTIP =
  'Counts over the exchanges shown here, none of them in an agreed period: how many are saved as confirmed, and how many were paid and settled by your wallet.'

/** Where a check result in the checks panel came from, in words. */
export const CHECK_SOURCE_WORDS = { here: 'checked here', node: 'node says' } as const
export const CHECK_SOURCE_LEGEND =
  '✓ checked here: your browser redid it just now. ◐ node says: taken from this node without re-checking. ○ not set up. — nothing to check yet.'

/** Said on the page, always, while this node keeps exchange text: where it
 *  is, how long, and that it is not shared. */
export function exchangeTextKeptNotice(days: number): string {
  const unit = days === 1 ? 'day' : 'days'
  return `This node keeps the text of exchanges on its own disk (deleted after ${days} ${unit}). Nothing is shared.`
}

/** Said on the page while keeping is off but kept text is still on disk:
 *  how many, when it goes, and that it can go now. */
export function exchangeTextStillHeldNotice(count: number, days: number): string {
  const texts = count === 1 ? 'kept text' : 'kept texts'
  const unit = days === 1 ? 'day' : 'days'
  return `This node still holds ${count} ${texts} on its own disk (deleted after ${days} ${unit}, or delete them now). Nothing is shared.`
}

/** The notice's action while kept text is still held. */
export const EXCHANGE_TEXT_DELETE_NOW = 'Delete now'

/** A service evidence agreement's coverage of one exchange, as this node
 *  works it out from its own records (docs/AGREEMENTS.md). */
export const AGREEMENT_COVERAGE_TOOLTIPS = {
  covered:
    'This exchange cites the service evidence agreement and is inside its window, its exchange count and its spend cap, by this node’s own records.',
  outside_window: 'This exchange cites the agreement, but its time is outside the agreement’s window.',
  over_count:
    'This exchange cites the agreement, but counting it, more exchanges cite the agreement than the agreement allows.',
  over_cap:
    'This exchange cites the agreement, but the spend this node observed up to it is over the spend cap. The exchange itself did not fail.',
  cap_not_evaluable:
    'A payment under the agreement has no observation on this node yet, so the spend shown is a lower bound and the cap can’t be checked.',
  set_up_after: 'This exchange cites no agreement: the first agreement with this peer was set up after it.',
  not_cited: 'An agreement with this peer covers this exchange’s time, but the exchange does not cite it.',
  no_agreement: 'No service evidence agreement with this peer covers this exchange.',
  not_evaluated: 'This exchange cites an agreement this node does not keep, so its coverage isn’t worked out here.'
} as const

/** The interop profile's finding on when the agreement was accepted. */
export const AGREEMENT_FINDING_TOOLTIPS = {
  accepted_before_action:
    'The requester’s signed receipt shows the agreement was accepted before the provider’s record of this exchange.',
  accepted_execution_cites:
    'The provider’s record cites the accepted agreement, but the times held can’t show which came first: they are kept to the minute.',
  accepted_not_cited: 'The agreement was accepted, but the provider’s record of this exchange does not cite it.',
  not_accepted: 'No accepted agreement that this node could check covers this exchange.',
  accepted_after_action: 'The agreement was accepted after the provider’s record of this exchange.',
  not_evaluated: 'Not checked yet: this node does not hold the provider’s record of this exchange.',
  evaluation_failed: 'Not checked: this node could not complete the check on the records it holds.'
} as const

export const AGREEMENT_SIDE_TOOLTIP =
  'Worked out by this node alone, from its own records. The other side keeps its own figures, and the requester’s count can be higher than the provider’s.'

export const AGREEMENT_SPEND_TOOLTIP =
  'The spend cap is the requester’s own assertion, not something either wallet enforces. The spend is what this node’s own payment records observed.'

