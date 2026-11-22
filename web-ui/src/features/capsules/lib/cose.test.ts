import { describe, expect, it } from 'vitest'
import { claimsKeysOutOfOrder } from '@/features/capsules/lib/cose'

const text = (s: string) => [0x60 + s.length, ...new TextEncoder().encode(s)]
const longText = (s: string) => [0x78, s.length, ...new TextEncoder().encode(s)]
const map = (...pairs: number[][]) => Uint8Array.from([0xa0 + pairs.length, ...pairs.flat()])

describe('claimsKeysOutOfOrder', () => {
  it('is true for the insertion order a pre-0.2.1 checkpoint lists (commitment before issued_at)', () => {
    expect(claimsKeysOutOfOrder(map([...text('log_size'), 1], [...text('commitment'), 0], [...text('issued_at'), 0]))).toBe(true)
  })

  it('is false for deterministic order, shorter key first then bytewise', () => {
    expect(claimsKeysOutOfOrder(map([...text('kind'), 0], [...text('log_size'), 1], [...text('issued_at'), 0], [...text('prev_size'), 0]))).toBe(false)
  })

  it('orders keys of 23 and 24 bytes by their longer encoding', () => {
    const k23 = 'a'.repeat(23)
    const k24 = 'a'.repeat(24)
    expect(claimsKeysOutOfOrder(map([...text(k23), 0], [...longText(k24), 0]))).toBe(false)
    expect(claimsKeysOutOfOrder(map([...longText(k24), 0], [...text(k23), 0]))).toBe(true)
  })

  it('is false when the order was not read: not a map, a key that is not text, or bytes it cannot parse', () => {
    expect(claimsKeysOutOfOrder(Uint8Array.from([0x80]))).toBe(false)
    expect(claimsKeysOutOfOrder(Uint8Array.from([0xa2, 0x02, 0x00, 0x01, 0x00]))).toBe(false)
    expect(claimsKeysOutOfOrder(Uint8Array.from([0xa1, ...text('a'), 0xf9, 0x3c, 0x00]))).toBe(false)
  })
})
