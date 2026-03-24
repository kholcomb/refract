/**
 * Fixture for test_no_assertion detection.
 * This test intentionally has no expect() calls.
 */

describe('empty', () => {
  it('does nothing', () => {
    const x = 1                           // antipattern: test_no_assertion
  })
})
