// The receipt on an Exchanges row (Mesh-LLM/capsules-plugin#96, #134): the
// owner's own receipt bundle for a paid exchange, fetched from this node on a
// click (the node may sign a checkpoint to serve it), checked in this browser
// by the agent-action-capsule runtime, and placed in one of three cases.
// Read-only: no score, no amount, nothing beyond what the runtime verified.
import { useState } from 'react'
import { Button } from '@/components/ui/button'
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'
import { fetchReceipt } from '@/features/capsules/api/receiptClient'
import { saveTextFile } from '@/features/capsules/lib/exchange-export'
import {
  RECEIPT_NOT_YET,
  receiptLabel,
  receiptLines,
  receiptRequest,
  receiptView,
  type ReceiptView
} from '@/features/capsules/lib/receipt-view'

type State = { phase: 'idle' } | { phase: 'checking' } | { phase: 'done'; view: ReceiptView }

const BUTTON_CLASS = 'ui-control h-7 w-fit gap-1 rounded-[var(--radius)] px-2 text-[length:var(--density-type-caption)]'

/** Hand the owner their own bundle as a file, the bytes the node served, to
 *  check it with a full verifier (the offline viewer). A click, a local Blob,
 *  nothing sent. */
function saveBundle(bundleText: string): void {
  saveTextFile('receipt-bundle.json', bundleText, 'application/json')
}

export function ReceiptPanel({ row }: { row: PaneCRow }) {
  const request = receiptRequest(row)
  const [state, setState] = useState<State>({ phase: 'idle' })
  if (!request) return null

  async function check() {
    if (!request) return
    setState({ phase: 'checking' })
    try {
      setState({ phase: 'done', view: await receiptView(await fetchReceipt(request)) })
    } catch (error) {
      setState({
        phase: 'done',
        view: { kind: 'error', message: error instanceof Error ? error.message : String(error) }
      })
    }
  }

  const view = state.phase === 'done' ? state.view : null
  const label = view ? receiptLabel(view) : null
  // The viewer's lines for the view (capsule-viewer's receipt words): for a
  // checked receipt the label line is drawn apart, then the rest.
  const lines = view ? receiptLines(view) : null
  return (
    <div
      aria-label="receipt"
      className="flex flex-wrap items-center gap-2 text-xs"
      data-receipt-side={request.side}
      role="group"
    >
      {/* The button stays mounted, so focus is not lost and the owner can ask again. */}
      <Button
        className={BUTTON_CLASS}
        disabled={state.phase === 'checking'}
        onClick={() => void check()}
        size="sm"
        type="button"
        variant="outline"
      >
        {state.phase === 'idle' ? 'Check receipt' : 'Check again'}
      </Button>
      <span aria-live="polite" className="contents" role="status">
        {state.phase === 'checking' ? <span className="text-fg-dim">Checking the receipt…</span> : null}
        {label ? (
          <span className="text-foreground" data-receipt-case={label}>
            Receipt: {label}
          </span>
        ) : null}
        {view?.kind === 'checked' ? (
          <span className="text-fg-dim">
            {lines?.lines.slice(1).join(' ')}
          </span>
        ) : null}
        {view?.kind === 'no_record' ? (
          <span className="text-fg-dim">{view.why}</span>
        ) : null}
        {view?.kind === 'no_receipt_yet' ? (
          <span className="text-fg-dim" data-receipt-case="no-receipt-yet">
            {RECEIPT_NOT_YET} {view.why}
          </span>
        ) : null}
        {view?.kind === 'cannot_check' ? (
          <span className="text-fg-dim" data-receipt-case="cannot-check">
            {lines?.lines.join(' ')}
          </span>
        ) : null}
        {view?.kind === 'not_drawn' ? (
          <span className="text-fg-dim" data-receipt-case="not-drawn">
            {lines?.lines.join(' ')}
          </span>
        ) : null}
        {view?.kind === 'did_not_verify' ? (
          <span className="text-fg-dim" data-receipt-case="did-not-verify">
            {lines?.lines.join(' ')}
          </span>
        ) : null}
        {view?.kind === 'error' ? (
          <span className="text-fg-dim" data-receipt-case="error">
            The receipt could not be loaded here: {view.message}
          </span>
        ) : null}
      </span>
      {view?.kind === 'cannot_check' || view?.kind === 'did_not_verify' || view?.kind === 'not_drawn' ? (
        <Button
          className={BUTTON_CLASS}
          onClick={() => saveBundle(view.bundleText)}
          size="sm"
          type="button"
          variant="outline"
        >
          Save bundle
        </Button>
      ) : null}
    </div>
  )
}
