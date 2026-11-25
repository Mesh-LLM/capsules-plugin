// The receipt export and the page's own code must check with one runtime, the
// browser build the page ships (vite-shared.ts): the shared alias maps the bare
// name, and vitest inlines capsule-viewer so the alias reaches it.
import * as bare from '@action-state-group/agent-action-capsule'
import * as browser from '@aac-browser'
import { describe, expect, it } from 'vitest'

describe('agent-action-capsule runtime', () => {
  it('is one module under its bare name and @aac-browser', () => {
    expect(bare.buildVerifiedBundleContext).toBe(browser.buildVerifiedBundleContext)
  })
})
