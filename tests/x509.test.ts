import { before, describe, it } from 'node:test'
import assert, { strictEqual } from 'node:assert'

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
        new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: 'animo.id' }]),
        new x509.SubjectAlternativeNameExtension([{ type: 'url', value: 'animo.id' }]),
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

    const nodejsPrivateKey = await webCrypto.subtle.importKey('jwk', jwkPrivate, alg, true, ['sign'])

    const nodejsPublicKey = await webCrypto.subtle.importKey('jwk', jwkPublic, alg, true, ['verify'])

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

  it('Validate a certificate chain', async () => {
    const crypto = new Crypto()
    x509.cryptoProvider.set(crypto)

    const alg = {
      name: 'ECDSA',
      namedCurve: 'p-256',
      hash: 'SHA-256',
    }

    const rootKeys = await crypto.subtle.generateKey(alg, true, ['sign', 'verify'])
    const rootCert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: '01',
      name: 'CN=Root',
      notBefore: new Date(),
      notAfter: new Date(),
      keys: rootKeys,
      signingAlgorithm: alg,
    })

    const intermediateKeys = await crypto.subtle.generateKey(alg, true, ['sign', 'verify'])
    const intermediateCert = await x509.X509CertificateGenerator.create({
      serialNumber: '02',
      subject: 'CN=Intermediate',
      issuer: rootCert.subject,
      notBefore: new Date(),
      notAfter: new Date(),
      signingKey: rootKeys.privateKey,
      publicKey: intermediateKeys.publicKey,
      signingAlgorithm: alg,
    })

    const leafKeys = await crypto.subtle.generateKey(alg, true, ['sign', 'verify'])
    const leafCert = await x509.X509CertificateGenerator.create({
      serialNumber: '03',
      subject: 'CN=Leaf',
      issuer: intermediateCert.subject,
      notBefore: new Date(),
      notAfter: new Date(),
      signingKey: intermediateKeys.privateKey,
      publicKey: leafKeys.publicKey,
      signingAlgorithm: alg,
    })

    const chain = new x509.X509ChainBuilder({
      certificates: [rootCert, intermediateCert, leafCert],
    })

    const items = await chain.build(leafCert)

    const encodedChain = items.map((i) => i.toString('base64'))

    const cert = new x509.X509Certificate(encodedChain[encodedChain.length - 1])
    console.log(cert.subject)

    strictEqual(items.length, 3)
  })

  /**
   *
   * The encoded chain is created by the function above and calling:
   *
   * ```js
   * const encodedChain = items.reverse().map((i) => i.toString('base64'))
   *
   * ```
   *
   * NOTE: it is important to call `reverse`, otherwise the expected order of the `x509.X509ChainBuilder` is incorrect
   *
   * It can be checked by the following code:
   *
   * ```js
   *
   *  const encodedChain = items.map((i) => i.toString("base64"));
   *  const expectedLeafCertificate = encodedChain[encodedChain.length - 1]
   *
   *  const cert = new x509.X509Certificate(expectedLeafCertificate);
   *
   *  console.log(cert.subject); // It is expected that the last item has `CN=LEAF`, but actually contains: `CN=ROOT`
   *
   * ```
   */
  it('validate encoded chain', async () => {
    const encodedChain = [
      // ROOT CERTIFICATE
      'MIHkMIGMoAMCAQICAQEwCgYIKoZIzj0EAwIwDzENMAsGA1UEAxMEUm9vdDAeFw0yNDA2MjQxMzI1NTJaFw0yNDA2MjQxMzI1NTJaMA8xDTALBgNVBAMTBFJvb3QwMDAKBggqhkjOPQQDAgMiAAI8UeZJn45YWj4WHv3bTCezXxPuhwtkk3F3u6msCf9ToKMCMAAwCgYIKoZIzj0EAwIDRwAwRAIgblzGh8QPLCTdgYrH3tJNWLhs0aSQjf4KrIPjPU9XiK8CIG5EBhnNsGHcOhETKlZC+mT5Eb0FRw7Oj/EibNPpHMtY',

      // INTERMEDIATE CERTIFICATE
      'MIHsMIGUoAMCAQICAQIwCgYIKoZIzj0EAwIwDzENMAsGA1UEAxMEUm9vdDAeFw0yNDA2MjQxMzI1NTJaFw0yNDA2MjQxMzI1NTJaMBcxFTATBgNVBAMTDEludGVybWVkaWF0ZTAwMAoGCCqGSM49BAMCAyIAAnprwUeUM02E/s4SpOEWQJEdQDTcJ64gLOe6R6QxJ9CzowIwADAKBggqhkjOPQQDAgNHADBEAiB4PajeNPEF3CnE9SG01b3JhAASRLY9lOC9357FtVbAFQIga2mPVAnc1CZrmxzdigcVJqqZlzTmBtdmXkSIt5sbnjg=',

      // LEAF CERTIFICATE
      'MIHtMIGUoAMCAQICAQMwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAxMMSW50ZXJtZWRpYXRlMB4XDTI0MDYyNDEzMjU1MloXDTI0MDYyNDEzMjU1MlowDzENMAsGA1UEAxMETGVhZjAwMAoGCCqGSM49BAMCAyIAAgwXycvPjUv6wyTw8WpwkAdoc/NRdwdorltTi6LnPjTpowIwADAKBggqhkjOPQQDAgNIADBFAiEA14IOiIAJCgKMMpKUxee+UmU/W27DWG4P5tm1TdRyaWMCIFuX01CBJa9lFeJyenDR2Y4PER/H/mFsY3pSkbHCkyXa',
    ]

    const parsedChain = encodedChain.map((e) => new x509.X509Certificate(e))

    const chain = new x509.X509ChainBuilder({
      certificates: parsedChain,
    })

    const validatedChain = await chain.build(parsedChain[parsedChain.length - 1])

    strictEqual(validatedChain.length, 3)
  })
})
