import { injectable } from '@credo-ts/core'
import * as x509 from '@peculiar/x509'

import { Crypto } from '../index'

export type X509CertificateData = {
  algorithm: string
  key: Uint8Array
  extensions?: {
    subjectAlternativeName?: {
      dns?: string
    } & Record<string, unknown>
  }
}

@injectable()
export class X509Service {
  public constructor() {
    const crypto = new Crypto()
    x509.cryptoProvider.set(crypto)
  }

  /**
   *
   * Validate a X.509 certificate chain
   *
   * ## Validation:
   *
   * 1. Make sure atleast 1 is in the chain
   * 2. .... validation according to RFC 5280
   *
   */
  public validateCertificateChain(certificateChain: Array<string>) {
    // TODO: add validation according to RFC 5280
    // Throw an error when an issue is found
    // TODO:
    //   Check whether the first certificate has a `SAN-dns` of the `iss` field
    //   should this be done in the `verify` method as this is reused between the issue and verify function
    const certificate = certificateChain[0]
    if (!certificate) throw new Error('Certificate chain is empty')
  }

  /**
   *
   * Parse a base64-encoded certificate
   *
   */
  public parseCertificate(encodedCertificate: string): X509CertificateData {
    const certificate = new x509.X509Certificate(encodedCertificate)

    const extension = certificate.getExtension(x509.SubjectAlternativeNameExtension.NAME)

    if (!extension) {
      throw new Error('The cerificate requires a Subject Alternative Name extension')
    }

    const textObject = extension.toTextObject()

    // TODO: how do we extract the correct dns field from the SAN?
    const issuer = textObject.dns

    if (!issuer) {
      throw new Error('No dns type found in the Subject Alternative Name extension')
    }

    return {
      algorithm: certificate.publicKey.algorithm,
      // TODO: does it matter that this is in DER-format?
      key: this.convertDerToRawBytes(new Uint8Array(certificate.publicKey.rawData)),
      issuer: issuer,
    }
  }

  private convertDerToRawBytes(derKey: Uint8Array) {
    return derKey
  }
}
