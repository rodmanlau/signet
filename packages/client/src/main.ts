import { runSignetClient } from './run.js'

const code = await runSignetClient(process.argv.slice(2), (line) => {
  process.stdout.write(`${line}\n`)
})
process.exit(code)
