import { before, describe, it } from 'node:test'
import { strictEqual, notStrictEqual } from 'node:assert'

import { NodeJSAriesAskar } from '@hyperledger/aries-askar-nodejs/build/NodeJSAriesAskar'
import { registerAriesAskar } from '@hyperledger/aries-askar-shared'

// Disable global crypto from Node.js so we can make sure we actually use askar here
// @ts-ignore
global.crypto = undefined

import { Crypto } from '../src'
import { generateAsymmetricKeyTests } from './utils/genKeyTests'

describe('crypto', async () => {
  before(() => {
    registerAriesAskar({ askar: new NodeJSAriesAskar() })
  })

  describe('random', async () => {
    it('generate random bytes', async () => {
      const crypto = new Crypto()
      const buf = new Uint8Array(100)
      const sameBuf = crypto.getRandomValues(buf)
      strictEqual(buf, sameBuf)
      notStrictEqual(buf.filter((i) => i === 0).length, 100)
    })
  })

  generateAsymmetricKeyTests(new Crypto(), [
    { name: 'ed25519' },
    { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } },
  ])
})
