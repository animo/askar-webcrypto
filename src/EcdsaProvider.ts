import { AsnConvert } from '@peculiar/asn1-schema'
import { SubjectPublicKeyInfo } from '@peculiar/asn1-x509'
import { ecdsaWithSHA256 } from '@peculiar/asn1-ecc'
import * as core from 'webcrypto-core'
import { askarKeyGenerate, askarKeyGetPublicBytes, askarKeySign, askarKeyVerify } from './askar'
import type { CryptoKeyPair, EcKeyGenParams, EcdsaParams, JsonWebKey, KeyFormat, KeyUsage } from './types'

export class EcdsaProvider extends core.EcdsaProvider {
  public async onSign(algorithm: EcdsaParams, key: core.CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    if (algorithm.hash.name !== 'SHA-256') {
      throw new Error(`Invalid hashing algorithm. Expected: 'SHA-256', received: ${algorithm.hash.name}`)
    }

    const signature = askarKeySign(key, data)

    return signature
  }

  public async onVerify(
    algorithm: EcdsaParams,
    key: core.CryptoKey,
    signature: ArrayBuffer,
    data: ArrayBuffer
  ): Promise<boolean> {
    if (algorithm.hash.name !== 'SHA-256') {
      throw new Error(`Invalid hashing algorithm. Expected: 'SHA-256', received: ${algorithm.hash.name}`)
    }

    const isValid = askarKeyVerify(key, data, signature)

    return isValid
  }

  public async onGenerateKey(
    algorithm: EcKeyGenParams,
    _extractable: boolean,
    _keyUsages: KeyUsage[]
  ): Promise<CryptoKeyPair> {
    const key = askarKeyGenerate(algorithm.namedCurve)

    return key
  }

  public async onExportKey(format: KeyFormat, key: core.CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    switch (format.toLowerCase()) {
      case 'pkcs8':
      case 'spki': {
        const publicKeyInfo = new SubjectPublicKeyInfo({
          algorithm: ecdsaWithSHA256,
          subjectPublicKey: askarKeyGetPublicBytes(key).buffer,
        })

        const derEncoded = AsnConvert.serialize(publicKeyInfo)
        return derEncoded
      }
      case 'raw':
        return askarKeyGetPublicBytes(key).buffer
      default:
        throw new Error(`Not supported format: ${format}`)
    }
  }

  onImportKey(
    _format: unknown,
    _keyData: unknown,
    _algorithm: unknown,
    _extractable: boolean,
    _keyUsages: KeyUsage[]
  ): Promise<core.CryptoKey> {
    throw new Error('onImportKey not implemented.')
  }
}
