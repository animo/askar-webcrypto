import { before, describe, it } from 'node:test'
import assert from 'node:assert'

import { Crypto as WebCrypto } from '@peculiar/webcrypto'

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

    const keys = await crypto.subtle.generateKey(alg, true, ['sign', 'verify'])

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

    const isValid = await cert.verify({
      signatureOnly: true,
      publicKey: keys.publicKey,
    })

    assert(cert.toString('pem').startsWith('-----BEGIN CERTIFICATE-----'))
    assert(cert.toString('pem').endsWith('-----END CERTIFICATE-----'))
    assert(isValid)
  })

  it('Self-signed Certificate comparison between askar and nodejs', async () => {
    const crypto = new Crypto()
    const webCrypto = new WebCrypto()
    x509.cryptoProvider.set(crypto)

    const alg = {
      name: 'ECDSA',
      namedCurve: 'P-256',
      hash: { name: 'SHA-256' },
    }

    const askarKeys = await crypto.subtle.generateKey(alg, true, ['sign', 'verify'])

    const jwkPrivate = await crypto.subtle.exportKey('jwk', askarKeys.privateKey)

    const jwkPublic = await crypto.subtle.exportKey('jwk', askarKeys.publicKey)

    const nodejsPrivateKey = await webCrypto.subtle.importKey(
      'jwk',
      jwkPrivate,
      { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } },
      true,
      ['sign']
    )

    const nodejsPublicKey = await webCrypto.subtle.importKey(
      'jwk',
      jwkPublic,
      { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } },
      true,
      ['verify']
    )

    const now = new Date()

    const askarCert = await x509.X509CertificateGenerator.createSelfSigned({
      name: 'C=NL, O=Animo Solutions',
      signingAlgorithm: alg,
      keys: askarKeys,
      notAfter: now,
      notBefore: now,
      extensions: [
        await x509.SubjectKeyIdentifierExtension.create(askarKeys.publicKey),
        new x509.SubjectAlternativeNameExtension([
          { type: 'dns', value: 'paradym.id' },
          { type: 'dns', value: 'wallet.paradym.id' },
        ]),
      ],
    })

    const nodejsCert = await x509.X509CertificateGenerator.createSelfSigned(
      {
        name: 'C=NL, O=Animo Solutions',
        signingAlgorithm: alg,
        keys: { publicKey: nodejsPublicKey, privateKey: nodejsPrivateKey },
        notAfter: now,
        notBefore: now,
        extensions: [
          await x509.SubjectKeyIdentifierExtension.create(nodejsPublicKey, undefined, webCrypto),
          new x509.SubjectAlternativeNameExtension([
            { type: 'dns', value: 'paradym.id' },
            { type: 'dns', value: 'wallet.paradym.id' },
          ]),
        ],
      },
      webCrypto
    )

    // Validate that the askar-key created certificate is valid using the nodejs keys (same key)
    const isValidAskarCertificate = await askarCert.verify(
      {
        publicKey: nodejsPublicKey,
        signatureOnly: true,
      },
      webCrypto
    )

    // Validate that the nodejs-key created certificate is valid using the askar keys (same key)
    const isValidNodejsCertificate = await nodejsCert.verify({
      publicKey: askarKeys.publicKey,
      signatureOnly: true,
    })

    assert(isValidNodejsCertificate)
    assert(isValidAskarCertificate)
  })
})
