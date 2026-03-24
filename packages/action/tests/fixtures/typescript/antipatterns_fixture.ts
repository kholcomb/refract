/**
 * Synthetic TypeScript fixtures to test anti-pattern detection.
 * This file intentionally contains anti-patterns — do not use in production.
 */

// ── Deep nesting ──────────────────────────────────────────────────────────────
function processOrders(orders: any[]) {
  const results: any[] = []
  for (const order of orders) {
    if (order.active) {
      for (const item of order.items ?? []) {
        if (item.available) {
          for (const variant of item.variants ?? []) {
            if (variant.stock > 0) {       // depth 4+
              results.push(variant)         // antipattern: deep_nesting
            }
          }
        }
      }
    }
  }
  return results
}

// ── Magic numbers ─────────────────────────────────────────────────────────────
function calculateDiscount(price: number): number {
  if (price > 999) {                       // antipattern: magic_number (999)
    return price * 0.85                     // antipattern: magic_number (0.85)
  } else if (price > 499) {                // antipattern: magic_number (499)
    return price * 0.92                     // antipattern: magic_number (0.92)
  }
  return price
}

// ── God class ─────────────────────────────────────────────────────────────────
class MegaController {
  method1() {}
  method2() {}
  method3() {}
  method4() {}
  method5() {}
  method6() {}
  method7() {}
  method8() {}
  method9() {}
  method10() {}
  method11() {}
  method12() {}
  method13() {}
  method14() {}
  method15() {}
  method16() {}                             // antipattern: god_class (16 methods)
}

// ── Assertion roulette (in a .test.ts-like block) ────────────────────────────
// Note: detection only triggers in files named *.test.ts or *.spec.ts
// The following patterns would be caught there:
//   expect(true).toBe(true)
//   expect(1).toBe(1)

// ── Hardcoded secret ─────────────────────────────────────────────────────────
const API_KEY = "sk-1234567890abcdef1234567890abcdef"    // antipattern: hardcoded_secret (gitleaks)

export { processOrders, calculateDiscount, MegaController, API_KEY }
