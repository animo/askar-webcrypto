import { before, describe, it } from 'node:test'

import { ariesAskar } from '@hyperledger/aries-askar-nodejs'

import { Agent, Buffer, type Key } from '@credo-ts/core'
import { AskarModule } from '@credo-ts/askar'
import { agentDependencies } from '@credo-ts/node'

// Disable global crypto from Node.js so we can make sure we actually use askar here
// @ts-ignore
global.crypto = undefined

import { CredoCryptoCallback, Crypto } from '../src'
import assert, { deepStrictEqual, strictEqual } from 'node:assert'

describe('crypto', async () => {
  let crypto: Crypto<Key>

  before(async () => {
    const agent = new Agent({
      config: {
        label: 'my-agent',
        walletConfig: { id: 'some-random-id', key: 'some-random-key' },
      },
      modules: {
        askar: new AskarModule({ ariesAskar }),
      },
      dependencies: agentDependencies,
    })

    await agent.initialize()

    crypto = new Crypto(new CredoCryptoCallback(agent.context))
  })

  describe('key gen', async () => {
    it('should generate key', async () => {
      const key = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } },
        false,
        ['sign', 'verify']
      )

      strictEqual(key.publicKey.type, 'public')
      strictEqual(key.privateKey.type, 'private')
    })

    it('should sign', async () => {
      const key = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } },
        false,
        ['sign', 'verify']
      )

      const data = Buffer.from('hello world!')

      const signature = await crypto.subtle.sign(
        {
          name: 'ECDSA',
          namedCurve: 'P-256',
          hash: { name: 'SHA-256' },
        } as unknown as AlgorithmIdentifier,
        key.privateKey,
        data
      )

      strictEqual(signature.byteLength, 64)
    })

    it('should verify', async () => {
      const key = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } },
        false,
        ['sign', 'verify']
      )

      const data = Buffer.from('hello world!')

      const signature = await crypto.subtle.sign(
        {
          name: 'ECDSA',
          namedCurve: 'P-256',
          hash: { name: 'SHA-256' },
        } as unknown as AlgorithmIdentifier,
        key.privateKey,
        data
      )

      const isValid = await crypto.subtle.verify(
        {
          name: 'ECDSA',
          namedCurve: 'P-256',
          hash: { name: 'SHA-256' },
        } as unknown as AlgorithmIdentifier,
        key.publicKey,
        signature,
        data
      )

      assert(isValid)
    })

    it('should export key to jwk', async () => {
      const key = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } },
        true,
        ['sign', 'verify']
      )

      const jwk = await crypto.subtle.exportKey('jwk', key.publicKey)

      strictEqual(jwk.kty, 'EC')
      strictEqual(jwk.crv, 'P-256')
    })

    it('should export key to spki', async () => {
      const key = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } },
        true,
        ['sign', 'verify']
      )

      const subjectPublicKeyInfo = await crypto.subtle.exportKey('spki', key.publicKey)

      strictEqual(subjectPublicKeyInfo.byteLength, 50)
    })

    it('should export key to jwk and import', async () => {
      const key = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } },
        true,
        ['sign', 'verify']
      )

      const jwk = await crypto.subtle.exportKey('jwk', key.publicKey)

      const importedKey = await crypto.subtle.importKey('jwk', jwk, key.publicKey.algorithm, true, ['verify'])

      deepStrictEqual(importedKey.algorithm, key.publicKey.algorithm)
    })

    it('should export key to spki and import', async () => {
      const key = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } },
        true,
        ['sign', 'verify']
      )

      const spki = await crypto.subtle.exportKey('spki', key.publicKey)

      const importedKey = await crypto.subtle.importKey('spki', spki, key.publicKey.algorithm, true, ['verify'])

      deepStrictEqual(importedKey.algorithm, key.publicKey.algorithm)
    })
  })
})
