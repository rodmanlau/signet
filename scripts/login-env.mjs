export function applyLoginEnv(base, text, envPath) {
  const env = { ...base }
  for (const line of text.split(/\r?\n/)) {
    if (line === '' || line.startsWith('#')) continue
    const eq = line.indexOf('=')
    if (eq <= 0) throw new Error(`bad line in ${envPath}`)
    const name = line.slice(0, eq)
    if (env[name] === undefined) env[name] = line.slice(eq + 1)
  }
  return env
}
