// Guards that the build and the dev harness resolve the Evidence page the same
// way (#344): both configs must carry every shared alias and the ?iife plugin.
import { describe, expect, it } from 'vitest'
import buildConfig from './vite.config.ts'
import devConfig from './vite.dev.config.ts'
import { sharedAliases } from './vite-shared.ts'

const pluginNames = (c: { plugins?: unknown }) =>
  (c.plugins as { name?: string }[]).flat(Infinity as 1).map((p) => p?.name)

describe.each([
  ['build', buildConfig],
  ['dev', devConfig]
])('%s config', (_n, config) => {
  it('uses the shared aliases', () => {
    expect(config.resolve?.alias).toBe(sharedAliases)
    expect(Object.keys(sharedAliases)).toEqual(expect.arrayContaining(['@', '@cll-browser', '@aac-browser']))
  })
  it('has the capsules:inline-iife plugin', () => {
    expect(pluginNames(config)).toContain('capsules:inline-iife')
  })
})
