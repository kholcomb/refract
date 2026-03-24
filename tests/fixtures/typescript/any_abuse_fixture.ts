/**
 * Fixture for any-type-abuse detection.
 * Intentionally uses excessive `any` annotations.
 */

// @ts-ignore bad import
import something from 'nonexistent'
// @ts-ignore another
const x = 1
// @ts-ignore yet another
const y = 2
// @ts-ignore four
const z = 3

function processData(input: any): any {       // any #1, #2
  const items: any[] = input.items             // any #3
  const config: any = input.config             // any #4
  const result: any = {}                       // any #5
  const callback: any = input.cb               // any #6
  return result as any                         // any #7 — triggers any_type_abuse
}

function transform(data: any, opts: any): any { // any #8, #9, #10
  return null
}

// Callback hell fixture
function callbackHell() {
  fetch('/a', (resA: any) => {
    fetch('/b', (resB: any) => {
      fetch('/c', (resC: any) => {
        fetch('/d', (resD: any) => {          // depth 4 — triggers callback_hell
          console.log(resD)
        })
      })
    })
  })
}

export { processData, transform, callbackHell }
