/**
 * Fixture for non_null_assertion detection.
 * Intentionally has >5 non-null assertions.
 */

interface Config {
  host?: string
  port?: number
  db?: { name?: string; user?: string; pass?: string; timeout?: number }
}

function connectToDatabase(config: Config) {
  const host = config.host!                // non-null #1
  const port = config.port!                // non-null #2
  const dbName = config.db!.name!          // non-null #3, #4
  const dbUser = config.db!.user!          // non-null #5, #6 -- triggers non_null_assertion
  const dbPass = config.db!.pass!          // non-null #7, #8
  return `${host}:${port}/${dbName}?user=${dbUser}&pass=${dbPass}`
}

export { connectToDatabase }
