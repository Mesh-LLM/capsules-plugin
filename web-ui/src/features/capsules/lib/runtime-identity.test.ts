// The shared alias maps agent-action-capsule's bare name to the browser build
// the page ships, the same module as @aac-browser (vite-shared.ts). That the
// alias reaches capsule-viewer in vitest, and that both pins agree, is held in
// vite-shared.test.ts.
import * as bare from '@action-state-group/agent-action-capsule'
import * as browser from '@aac-browser'
import { describe, expect, it } from 'vitest'

describe('agent-action-capsule runtime', () => {
  it('is one module under its bare name and @aac-browser', () => {
    expect(bare.buildVerifiedBundleContext).toBe(browser.buildVerifiedBundleContext)
  })
})
