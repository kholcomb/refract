/**
 * Fixture for console_log_left detection.
 * Intentionally has >3 console.log calls.
 */

function doWork() {
  console.log("starting work")           // console #1
  console.log("processing step 1")       // console #2
  console.debug("debug info")            // console #3
  console.log("processing step 2")       // console #4 -- triggers console_log_left
  return true
}

export { doWork }
