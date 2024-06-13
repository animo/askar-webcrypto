import { before, describe, it } from 'node:test'
import assert from 'node:assert'

import { NodeJSAriesAskar } from '@hyperledger/aries-askar-nodejs/build/NodeJSAriesAskar'
import { registerAriesAskar } from '@hyperledger/aries-askar-shared'
import * as x509 from '@peculiar/x509'

import { Crypto } from '../src'

describe('x509', async () => {
  before(() => {
    registerAriesAskar({ askar: new NodeJSAriesAskar() })
  })

  it('Self-signed Certificate', async () => {
    const crypto = new Crypto()
    x509.cryptoProvider.set(crypto)

    const alg = {
      name: 'ECDSA',
      namedCurve: 'P-256',
      hash: { name: 'SHA-256' },
    }

    const keys = await crypto.subtle.generateKey(alg, false, ['sign', 'verify'])

    const cert = await x509.X509CertificateGenerator.createSelfSigned({
      name: 'C=NL, O=Animo Solutions',
      signingAlgorithm: alg,
      keys,
      extensions: [
        await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
        new x509.SubjectAlternativeNameExtension([
          { type: 'dns', value: 'paradym.id' },
          { type: 'dns', value: 'wallet.paradym.id' },
        ]),
      ],
    })

    assert(cert.toString('pem').startsWith('-----BEGIN CERTIFICATE-----'))
    assert(cert.toString('pem').endsWith('-----END CERTIFICATE-----'))
  })
})
