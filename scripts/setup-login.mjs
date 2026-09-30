import { randomBytes } from 'node:crypto'
import { access, mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { getPublicKeyAsync } from '@noble/ed25519'

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const dir = resolve(process.argv[2] ?? join(repoRoot, '.valar', 'login'))
const privatePath = join(dir, 'private-key')
const derivationPath = join(dir, 'derivation-key')
const publicPath = join(dir, 'identity-keys.json')
const envPath = join(dir, 'login.env')
const sessionsPath = join(dir, 'sessions.json')

async function exists(path) {
  try {
    await access(path)
    return true
  } catch {
    return false
  }
}

async function readKey(path) {
  const bytes = await readFile(path)
  if (bytes.length !== 32) {
    process.stderr.write(`${path} must be 32 bytes\n`)
    process.exit(1)
  }
  return bytes
}

await mkdir(dir, { recursive: true })
const hasPrivate = await exists(privatePath)
const hasDerivation = await exists(derivationPath)
if (hasPrivate !== hasDerivation) {
  process.stderr.write('refusing to mint one key beside an existing key\n')
  process.exit(1)
}

let privateKey
let derivationKey
if (!hasPrivate) {
  privateKey = randomBytes(32)
  derivationKey = randomBytes(32)
  await writeFile(privatePath, privateKey, { mode: 0o600, flag: 'wx' })
  await writeFile(derivationPath, derivationKey, { mode: 0o600, flag: 'wx' })
  process.stdout.write('created signing key and derivation key\n')
} else {
  privateKey = await readKey(privatePath)
  derivationKey = await readKey(derivationPath)
  process.stdout.write('keeping existing keys\n')
}
if (privateKey.equals(derivationKey)) {
  process.stderr.write('derivation key and signing key must differ\n')
  process.exit(1)
}

const publicKey = Buffer.from(await getPublicKeyAsync(privateKey))
const published = JSON.stringify([{ id: 'k1', publicKey: publicKey.toString('base64') }], null, 2)
await writeFile(publicPath, `${published}\n`)

if (!(await exists(envPath))) {
  const lines = [
    `SIGNET_SESSIONS=${sessionsPath}`,
    `SIGNET_PRIVATE_KEY=${privateKey.toString('base64')}`,
    `SIGNET_DERIVATION_KEY=${derivationKey.toString('base64')}`,
    'SIGNET_KEY_ID=k1',
    'SIGNET_TEST=1',
    '',
  ]
  await writeFile(envPath, lines.join('\n'), { mode: 0o600, flag: 'wx' })
  process.stdout.write(`wrote ${envPath}\n`)
} else {
  process.stdout.write(`keeping ${envPath}\n`)
}
process.stdout.write(`public keys for world servers: ${publicPath}\n`)
const start = process.argv[2] ? `node scripts/start-login.mjs ${dir}` : 'node scripts/start-login.mjs'
process.stdout.write(`start with: ${start}\n`)
