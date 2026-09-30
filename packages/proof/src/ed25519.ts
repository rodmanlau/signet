import { hashes } from '@noble/ed25519'
import { sha512 } from '@noble/hashes/sha2.js'

// Sync verify and sign need a SHA-512. Callers that only import the readers never load this file.
hashes.sha512 = (message) => sha512(message)
