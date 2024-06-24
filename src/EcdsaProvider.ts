import { AsnConvert, AsnParser } from '@peculiar/asn1-schema'
import { SubjectPublicKeyInfo } from '@peculiar/asn1-x509'
import { ecdsaWithSHA256 } from '@peculiar/asn1-ecc'
import * as core from 'webcrypto-core'
import {
  askarExportKeyToJwk,
  askarKeyGenerate,
  askarKeyGetPublicBytes,
  askarKeySign,
  askarKeyVerify,
  askarKeyFromJwk,
  askarKeyFromPublicBytes,
} from './askar'
import type {
  CryptoKeyPair,
  EcKeyGenParams,
  EcKeyImportParams,
  EcdsaParams,
  JsonWebKey,
  KeyFormat,
  KeyUsage,
} from './types'

export class EcdsaProvider extends core.EcdsaProvider {
  public async onSign(algorithm: EcdsaParams, key: core.CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    if (algorithm.hash.name !== 'SHA-256') {
      throw new Error(`Invalid hashing algorithm. Expected: 'SHA-256', received: ${algorithm.hash.name}`)
    }

    const signature = askarKeySign({ key, data })

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

    const isValid = askarKeyVerify({ key, data, signature })

    return isValid
  }

  public async onGenerateKey(
    algorithm: EcKeyGenParams,
    extractable: boolean,
    keyUsages: KeyUsage[]
  ): Promise<CryptoKeyPair> {
    const key = askarKeyGenerate({ algorithm, extractable, keyUsages })

    return key
  }

  public async onExportKey(format: KeyFormat, key: core.CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    switch (format.toLowerCase()) {
      case 'spki': {
        const publicKeyInfo = new SubjectPublicKeyInfo({
          algorithm: ecdsaWithSHA256,
          subjectPublicKey: askarKeyGetPublicBytes(key).buffer,
        })

        const derEncoded = AsnConvert.serialize(publicKeyInfo)
        return derEncoded
      }
      case 'jwk':
        return askarExportKeyToJwk(key)
      case 'raw':
        return askarKeyGetPublicBytes(key).buffer
      default:
        throw new Error(`Not supported format: ${format}`)
    }
  }

  public async onImportKey(
    format: KeyFormat,
    keyData: JsonWebKey | ArrayBuffer,
    algorithm: EcKeyImportParams,
    extractable: boolean,
    keyUsages: KeyUsage[]
  ): Promise<core.CryptoKey> {
    if (format !== 'jwk' && ArrayBuffer.isView(keyData)) {
      throw new core.OperationError('non-jwk formats can only be used with an ArrayBuffer')
    }

    switch (format.toLowerCase()) {
      case 'jwk':
        return askarKeyFromJwk({
          extractable,
          keyUsages,
          keyData: keyData as JsonWebKey,
        })
      case 'spki': {
        const keyInfo = AsnParser.parse(new Uint8Array(keyData as ArrayBuffer), core.asn1.PublicKeyInfo)

        return askarKeyFromPublicBytes({
          format,
          keyData: new Uint8Array(keyInfo.publicKey),
          keyUsages,
          extractable,
          algorithm,
        })
      }
      default:
        throw new core.OperationError(`Only format 'jwt' is supported for importing keys. Received: ${format}`)
    }
  }
}
