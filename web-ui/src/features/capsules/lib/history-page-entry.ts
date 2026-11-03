// What a saved History page runs: the verifier, the map from its result to
// the shared view's input, and the view itself. Bundled as one IIFE into
// every saved History page (`saved-pages.ts`).
import { renderHistoryView } from '@action-state-group/capsule-viewer/history-view'

export { verifyHistoryReply } from '@/features/capsules/lib/history-verify'
export { historyViewInput } from '@/features/capsules/lib/history-view-input'
export { renderHistoryView }
