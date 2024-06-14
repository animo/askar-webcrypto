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

  describe('equal to node', async () => {
    const c = require('node:crypto') as Crypto

    const p256KeyNodeJs = await c.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      true,
      ['sign', 'verify']
    )

    const p256KeyAskar = await new Crypto().subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      true,
      ['sign', 'verify']
    )

    const publicKeyNodejs = await c.subtle.exportKey('raw', p256KeyNodeJs.publicKey)
    const publicKeyAskar = await new Crypto().subtle.exportKey('raw', p256KeyAskar.publicKey)

    // 33 for compressed format and 65 for uncompressed
    strictEqual(publicKeyAskar.byteLength, 33)
    strictEqual(publicKeyNodejs.byteLength, 65)
  })

  generateAsymmetricKeyTests(new Crypto(), [
    { name: 'ed25519' },
    { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } },
  ])
})
