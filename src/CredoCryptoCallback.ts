import { type AgentContext, Buffer, type JwkJson, Key, KeyType, getJwkFromJson, getJwkFromKey } from '@credo-ts/core'
import { AsnConvert, AsnParser } from '@peculiar/asn1-schema'
import { type AlgorithmIdentifier, SubjectPublicKeyInfo } from '@peculiar/asn1-x509'
import { CallbackCryptoKey } from './CallbackKey'
import type { CryptoCallback } from './CryptoCallback'
import type {
  JsonWebKey,
  KeyAlgorithm,
  KeyFormat,
  KeyImportParams,
  KeySignParams,
  KeyUsage,
  KeyVerifyParams,
} from './types'
import { ecdsaWithSHA256 } from '@peculiar/asn1-ecc'

export class CredoCryptoCallback implements CryptoCallback<Key> {
  public constructor(private agentContext: AgentContext) {}

  public async sign(key: CallbackCryptoKey<Key>, message: Uint8Array, _algorithm: KeySignParams): Promise<Uint8Array> {
    const signature = await this.agentContext.wallet.sign({
      key: key.key,
      data: Buffer.from(message),
    })

    return signature
  }

  public async verify(
    key: CallbackCryptoKey<Key>,
    _algorithm: KeyVerifyParams,
    message: Uint8Array,
    signature: Uint8Array
  ): Promise<boolean> {
    const isValidSignature = await this.agentContext.wallet.verify({
      key: key.key,
      signature: Buffer.from(signature),
      data: Buffer.from(message),
    })

    return isValidSignature
  }

  public async generate(algorithm: KeyAlgorithm): Promise<Key> {
    const keyType = cryptoKeyAlgorithmToCredoKeyType(algorithm)

    const key = await this.agentContext.wallet.createKey({
      keyType,
    })

    return key
  }

  public async importKey(
    format: KeyFormat,
    keyData: Uint8Array | JsonWebKey,
    algorithm: KeyImportParams,
    extractable: boolean,
    keyUsages: Array<KeyUsage>
  ): Promise<CallbackCryptoKey<Key>> {
    if (format === 'jwk' && keyData instanceof Uint8Array) {
      throw new Error('JWK format is only allowed with a jwk as key data')
    }

    if (format !== 'jwk' && !(keyData instanceof Uint8Array)) {
      throw new Error('non-jwk formats are only allowed with a uint8array as key data')
    }

    switch (format.toLowerCase()) {
      case 'jwk': {
        const jwk = getJwkFromJson(keyData as unknown as JwkJson)
        const publicKey = Key.fromPublicKey(jwk.publicKey, jwk.keyType)
        return new CallbackCryptoKey(publicKey, algorithm, extractable, 'public', keyUsages)
      }
      case 'spki': {
        const subjectPublicKey = AsnParser.parse(keyData as Uint8Array, SubjectPublicKeyInfo)

        const key = new Uint8Array(subjectPublicKey.subjectPublicKey)

        const keyType = spkiAlgorithmIntoCredoKeyType(subjectPublicKey.algorithm)

        return new CallbackCryptoKey(Key.fromPublicKey(key, keyType), algorithm, extractable, 'public', keyUsages)
      }
      default:
        throw new Error(`Unsupported export format: ${format}`)
    }
  }

  public async exportKey(format: KeyFormat, key: CallbackCryptoKey<Key>): Promise<Uint8Array | JsonWebKey> {
    switch (format.toLowerCase()) {
      case 'jwk': {
        const jwk = getJwkFromKey(key.key)
        return jwk.toJson() as unknown as JsonWebKey
      }
      case 'spki': {
        const publicKeyInfo = new SubjectPublicKeyInfo({
          algorithm: ecdsaWithSHA256,
          subjectPublicKey: key.key.publicKey.buffer,
        })

        const derEncoded = AsnConvert.serialize(publicKeyInfo)
        return new Uint8Array(derEncoded)
      }

      default:
        throw new Error(`Unsupported export format: ${format}`)
    }
  }
}

// TODO: proper conversion
const cryptoKeyAlgorithmToCredoKeyType = (_algorithm: KeyAlgorithm): KeyType => KeyType.P256

// TODO: proper conversion
const spkiAlgorithmIntoCredoKeyType = (_algorithm: AlgorithmIdentifier): KeyType => KeyType.P256
