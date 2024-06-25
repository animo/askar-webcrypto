import * as core from 'webcrypto-core'

import { Key as AskarKey, Jwk } from '@hyperledger/aries-askar-shared'
import type { EcdsaParams, JsonWebKey, KeyAlgorithm, KeyFormat, KeyImportParams, KeyType, KeyUsage } from './types'
import { askarAlgorithmToCryptoAlgorithm, cryptoAlgorithmToAskarAlgorithm } from './askar'
import { AsnConvert, AsnParser } from '@peculiar/asn1-schema'
import { ecdsaWithSHA256 } from '@peculiar/asn1-ecc'
import { SubjectPublicKeyInfo } from '@peculiar/asn1-x509'

export class AskarCryptoKey extends core.CryptoKey {
  public askarKey: AskarKey

  public constructor({
    askarKey,
    algorithm,
    extractable = false,
    usages,
    type,
  }: {
    askarKey: AskarKey
    extractable?: boolean
    usages: Array<KeyUsage>
    type?: KeyType
    algorithm: KeyAlgorithm
  }) {
    super()
    this.askarKey = askarKey
    this.extractable = extractable
    this.type = type
    this.usages = usages
    this.algorithm = algorithm
  }

  public [Symbol.dispose]() {
    this.askarKey.handle.free()
  }

  public sign(algorithm: EcdsaParams, data: ArrayBuffer) {
    if (algorithm.hash && algorithm.hash.name !== 'SHA-256') {
      throw new Error(`Invalid hashing algorithm. Expected: 'SHA-256', received: ${algorithm.hash.name}`)
    }
    return this.askarKey.signMessage({ message: new Uint8Array(data) })
  }

  public verify(algorithm: EcdsaParams, signature: ArrayBuffer, data: ArrayBuffer) {
    if (algorithm.hash && algorithm.hash.name !== 'SHA-256') {
      throw new Error(`Invalid hashing algorithm. Expected: 'SHA-256', received: ${algorithm.hash.name}`)
    }

    return this.askarKey.verifySignature({
      message: new Uint8Array(data),
      signature: new Uint8Array(signature),
    })
  }

  public get publicBytes() {
    return this.askarKey.publicBytes
  }

  /**
   *
   * @todo - Deal with key format
   *
   */
  public static fromPublicBytes(
    algorithm: KeyImportParams,
    keyData: Uint8Array,
    _format: KeyFormat,
    extractable: boolean,
    keyUsages: Array<KeyUsage>
  ) {
    const publicKey = AskarKey.fromPublicBytes({
      algorithm: cryptoAlgorithmToAskarAlgorithm(algorithm),
      publicKey: keyData,
    })

    return new AskarCryptoKey({
      askarKey: publicKey,
      type: 'public',
      algorithm,
      usages: keyUsages,
      extractable,
    })
  }

  /**
   *
   * @todo - Deal with key format
   *
   */
  public static fromSecret(
    algorithm: KeyImportParams,
    keyData: Uint8Array,
    _format: KeyFormat,
    extractable: boolean,
    keyUsages: Array<KeyUsage>
  ) {
    const publicKey = AskarKey.fromSecretBytes({
      algorithm: cryptoAlgorithmToAskarAlgorithm(algorithm),
      secretKey: keyData,
    })

    return new AskarCryptoKey({
      askarKey: publicKey,
      type: 'private',
      algorithm,
      usages: keyUsages,
      extractable,
    })
  }

  public toJwk() {
    if (this.type === 'public') return this.askarKey.jwkPublic
    if (this.type === 'private' || this.type === 'secret') {
      return this.askarKey.jwkSecret
    }
  }

  public static fromJwk(keyData: JsonWebKey, keyUsages: Array<KeyUsage>, extractable: boolean) {
    const key = AskarKey.fromJwk({ jwk: new Jwk(keyData) })

    let type: KeyType = 'public'
    try {
      key.secretBytes
      type = 'private'
    } catch {}

    return new AskarCryptoKey({
      askarKey: key,
      extractable,
      usages: keyUsages,
      type,
      algorithm: askarAlgorithmToCryptoAlgorithm(key.algorithm),
    })
  }

  public static override create<T extends core.CryptoKey = AskarCryptoKey>(
    algorithm: KeyAlgorithm,
    type: KeyType,
    extractable: boolean,
    usages: core.KeyUsages
  ): T {
    return new AskarCryptoKey({
      askarKey: AskarKey.generate(cryptoAlgorithmToAskarAlgorithm(algorithm)),
      algorithm,
      extractable,
      usages,
      type,
    }) as unknown as T
  }

  public exportKey(format: KeyFormat): JsonWebKey | ArrayBuffer {
    switch (format.toLowerCase()) {
      case 'spki': {
        const publicKeyInfo = new SubjectPublicKeyInfo({
          algorithm: ecdsaWithSHA256,
          subjectPublicKey: this.publicBytes.buffer,
        })

        const derEncoded = AsnConvert.serialize(publicKeyInfo)
        return derEncoded
      }
      case 'jwk':
        return this.toJwk() as JsonWebKey
      case 'raw':
        // TODO: likely incorrect
        return this.publicBytes.buffer
      default:
        throw new Error(`Not supported format: ${format}`)
    }
  }

  public static importKey(
    format: KeyFormat,
    keyData: JsonWebKey | ArrayBuffer,
    algorithm: KeyAlgorithm,
    extractable: boolean,
    keyUsages: Array<KeyUsage>
  ) {
    if (format !== 'jwk' && ArrayBuffer.isView(keyData)) {
      throw new core.OperationError('non-jwk formats can only be used with an ArrayBuffer')
    }

    switch (format.toLowerCase()) {
      case 'jwk':
        return AskarCryptoKey.fromJwk(keyData as JsonWebKey, keyUsages, extractable)
      case 'spki': {
        const keyInfo = AsnParser.parse(new Uint8Array(keyData as ArrayBuffer), core.asn1.PublicKeyInfo)

        return AskarCryptoKey.fromPublicBytes(
          algorithm,
          new Uint8Array(keyInfo.publicKey),
          format,
          extractable,
          keyUsages
        )
      }
      default:
        throw new core.OperationError(
          `Only format 'jwt' and 'spki' are supported for importing keys. Received: ${format}`
        )
    }
  }
}

export const assertIsAskarCryptoKey = (askarKey: core.CryptoKey): AskarCryptoKey => {
  if (askarKey instanceof AskarCryptoKey) return askarKey
  throw new Error('key is not an instance of AskarCryptoKey')
}
