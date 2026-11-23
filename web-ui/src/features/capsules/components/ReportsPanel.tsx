// The page's "Reports" group (Mesh-LLM/capsules-plugin#96, #339): the
// evidencebook-report skill's grades, in its own words. Grade 2, the node's
// sealed EvidenceBook report, says before it is pressed whether there is one
// (`settlement-report/status`); pressing checks the page against its seal and
// saves it only on a match, else says why in words and saves nothing. Grade 3
// saves the History page. Grade 1 is a line: the dashboard has no agent.
import { useQuery } from '@tanstack/react-query'
import { useCallback, useState } from 'react'

import { Button } from '@/components/ui/button'
import {
  fetchServedHistory,
  fetchSettlementReport,
  fetchSettlementReportStatus
} from '@/features/capsules/api/client'
import { saveTextFile } from '@/features/capsules/lib/exchange-export'
import { historyPage, sealedSettlementPage } from '@/features/capsules/lib/saved-pages'
import {
  NARRATION_NEEDS_AGENT,
  SEALED_LABEL,
  STAMPED_LABEL,
  noReportNote,
  reportStatusLine,
  sealedNote
} from '@/features/capsules/lib/what-happened'

const BUTTON_CLASS =
  'ui-control h-8 gap-1.5 rounded-[var(--radius)] px-2.5 text-[length:var(--density-type-caption)]'

export function ReportsPanel() {
  const statusQuery = useQuery({
    queryKey: ['capsules', 'settlement-report-status'],
    queryFn: fetchSettlementReportStatus,
    staleTime: 60_000
  })
  const statusLine = statusQuery.data ? reportStatusLine(statusQuery.data) : null
  const [saving, setSaving] = useState<'history' | 'settlement' | null>(null)
  const [note, setNote] = useState<string | null>(null)

  const save = useCallback(
    async (which: 'history' | 'settlement') => {
      setSaving(which)
      setNote(null)
      try {
        const savedAt = new Date().toISOString().replace(/\.\d+Z$/, 'Z')
        if (which === 'settlement') {
          const report = await fetchSettlementReport()
          if (report.kind === 'refused') {
            setNote(noReportNote(report.why))
            return
          }
          const page = sealedSettlementPage(report.page, savedAt)
          setNote(
            saveTextFile(page.fileName, page.html, 'text/html')
              ? sealedNote(report.sealedAt, report.date)
              : 'This browser could not save the page.'
          )
        } else {
          const served = await fetchServedHistory()
          const page = historyPage(served.replyText, savedAt, served)
          if (!saveTextFile(page.fileName, page.html, 'text/html')) setNote('This browser could not save the page.')
        }
      } catch (error) {
        setNote(`Could not save the page: ${error instanceof Error ? error.message : 'this node did not answer'}.`)
      } finally {
        setSaving(null)
        if (which === 'settlement') void statusQuery.refetch()
      }
    },
    [statusQuery]
  )

  return (
    <section aria-labelledby="reports-heading" className="flex flex-col gap-1.5" data-testid="reports-panel">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-xs font-medium text-fg-dim" id="reports-heading">
          Reports
        </h2>
        <Button
          aria-describedby={statusLine ? 'report-status-line' : undefined}
          className={BUTTON_CLASS}
          disabled={saving !== null}
          onClick={() => void save('settlement')}
          size="sm"
          type="button"
          variant="outline"
        >
          {SEALED_LABEL}
        </Button>
        <Button
          className={BUTTON_CLASS}
          disabled={saving !== null}
          onClick={() => void save('history')}
          size="sm"
          type="button"
          variant="outline"
        >
          {STAMPED_LABEL}
        </Button>
      </div>
      {statusLine ? (
        <p className="text-xs text-fg-faint" id="report-status-line">
          {statusLine}
        </p>
      ) : null}
      {note ? (
        <p className="text-xs text-fg-faint" role="status">
          {note}
        </p>
      ) : null}
      <p className="text-xs text-fg-faint">{NARRATION_NEEDS_AGENT}</p>
    </section>
  )
}
