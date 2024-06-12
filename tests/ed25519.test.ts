import { before, describe } from 'node:test'

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

  generateAsymmetricKeyTests(new Crypto(), [
    { name: 'ed25519' },
    { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } },
  ])
})
