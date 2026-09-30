import { expect, it } from 'vitest'
import { applyLoginEnv } from '../../../scripts/login-env.mjs'

it('fills unset names and keeps a name the environment already has', () => {
  const env = applyLoginEnv(
    { SIGNET_HOST: '192.0.2.10', SIGNET_TEST: '', PATH: 'kept' },
    [
      'SIGNET_HOST=127.0.0.1',
      'SIGNET_ISSUER=http://127.0.0.1:8787',
      'SIGNET_SESSIONS=/tmp/sessions.json',
      'SIGNET_TEST=1',
      '# comment',
      '',
    ].join('\n'),
    'login.env',
  )
  expect(env.SIGNET_HOST).toBe('192.0.2.10')
  expect(env.SIGNET_TEST).toBe('')
  expect(env.SIGNET_ISSUER).toBe('http://127.0.0.1:8787')
  expect(env.SIGNET_SESSIONS).toBe('/tmp/sessions.json')
  expect(env.PATH).toBe('kept')
  expect(() => applyLoginEnv({}, 'NOEQUALS', 'login.env')).toThrow('bad line in login.env')
})
