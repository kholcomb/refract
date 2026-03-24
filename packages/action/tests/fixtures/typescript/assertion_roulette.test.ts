/**
 * Synthetic test fixture for assertion roulette and excessive mocking detection.
 * This file intentionally contains test smells — do not use in production.
 */

// ── Excessive mocking (6 mocks) ──────────────────────────────────────────────
jest.mock('./module1')
jest.mock('./module2')
jest.mock('./module3')
jest.mock('./module4')
jest.mock('./module5')
jest.mock('./module6')     // antipattern: excessive_mocking (>5 mocks)

describe('trivial tests', () => {
  it('should always pass (assertion roulette)', () => {
    expect(true).toBe(true)       // antipattern: assertion_roulette
    expect(1).toBe(1)             // antipattern: assertion_roulette
    expect(false).toBe(false)     // antipattern: assertion_roulette
  })
})
