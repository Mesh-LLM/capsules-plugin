// The Exchanges tab's "What happened" row (Mesh-LLM/capsules-plugin#96): one
// button per grade of the evidencebook-report skill
// (evidencebook-skills `skills/evidencebook-report/SKILL.md`), in the skill's
// own grade words. No score, grade letter or percentage.

/** Grade 1. A narration is an agent reading sealed records; the dashboard has
 *  no agent, so the button says where narration comes from and narrates
 *  nothing (Sherlock2, Q2 on #96). */
export const NARRATED_LABEL = 'Narrated by your agent'
export const NARRATION_NEEDS_AGENT =
  'Narration needs your agent: ask it, with the evidencebook-report skill, to read your sealed records. This dashboard has no agent, so it narrates nothing.'

/** Grade 2: the node's latest sealed report, checked against its seal when
 *  the node hands it over (`settlement_report.rs`). */
export const SEALED_LABEL = 'EvidenceBook report (sealed and checked)'

/** Grade 3: the History page here, and each paid exchange's receipt on its row. */
export const STAMPED_LABEL = 'Stamped: History page'

/** What the row says after saving the sealed report: when it was sealed and
 *  the day it reports up to, so a stale report shows as stale. */
export function sealedNote(sealedAt: string | null, date: string | null): string {
  return `Saved the EvidenceBook report sealed ${sealedAt ?? 'at an unrecorded time'}, reporting up to ${date ?? 'an unrecorded day'}. It matched its seal when the node handed it over.`
}

/** What the row says when the node has no sealed report to give. */
export function noReportNote(why: string): string {
  return `No report to give: ${why}. Saved a page that says so.`
}
