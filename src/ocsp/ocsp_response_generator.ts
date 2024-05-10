import * as ocsp from "@peculiar/asn1-ocsp";
import * as asn1X509 from "@peculiar/asn1-x509";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { container } from "tsyringe";
import { Convert } from "pvtsutils";
import { Extension } from "../extension";
import { cryptoProvider } from "../provider";
import { X509Certificate } from "../x509_cert";
import { OCSPResponse, OCSPResponseStatus } from "./ocsp_response";
import { AlgorithmProvider, diAlgorithmProvider } from "../algorithm";
import { IAsnSignatureFormatter, diAsnSignatureFormatter } from "../asn_signature_formatter";
import { HashedAlgorithm } from "../types";
import { PublicKey, PublicKeyType } from "../public_key";
import { BufferSourceConverter } from "pvtsutils";
import { Name } from "../name";
import { CertStatus } from "@peculiar/asn1-ocsp";


export interface SingleResponseInterface {
  /**
   * certificate to which the response applies
   */
  certificate: X509Certificate;
  /**
   * issuer of the certificate to which the response applies
   */
  issuer: X509Certificate;
  /**
   * certificate status
   */
  status: CertStatus;
  /**
   * Time the status of the certificate was last updated
   */
  thisUpdate: Date;
  /**
   * Time the status of the certificate will be next updated.
   * OPTIONAL, if nextUpdate is not set, the responder is indicating that newer
   * revocation information is available all the time.
   */
  nextUpdate?: Date;
  /**
   * List of single response extensions
   */
  extensions: Extension[];

}
export interface OCSPResponseCreateParams {
  /**
   * Response signature algorithm
   */
  signatureAlgorithm: AlgorithmIdentifier;
  /**
   * Response signing key
   */
  signingKey: CryptoKey;
  /**
   * the Single Response data for which the response is being generated
   */
  singleResponses: SingleResponseInterface[];
  /**
   * The certificate that will be used to sign the response
   */
  responder: PublicKeyType | Name;
  /**
   * List of certificates that can be used to verify the signature of the response
   */
  certificates?: X509Certificate[];
  /**
   * The date and time for which the status of the certificate is issued
   * The default is the current time
   */
  date?: Date;
  /**
   * Certificate status
   * The default is successful
   */
  status?: OCSPResponseStatus;
  /**
   * List of response extensions
   */
  extensions?: Extension[];
}

export class OCSPResponseGenerator {
  /**
   * Creates an OCSP response and signs it.
   * @param params OCSP response creation options.
   * @param crypto Crypto provider. Default is from CryptoProvider.
   * @returns OCSP response.
   */
  public static async create(params: OCSPResponseCreateParams, crypto = cryptoProvider.get()): Promise<OCSPResponse> {
    // assemble single responses
    const algProv = container.resolve<AlgorithmProvider>(diAlgorithmProvider);

    const responses: ocsp.SingleResponse[] = [];
    for(const singleResponse of params.singleResponses) {
      const response = new ocsp.SingleResponse({
        certID: new ocsp.CertID({
          // if hash algorithm is undefined use sha-1
          hashAlgorithm: algProv.toAsnAlgorithm({name: "SHA-1"}),
          issuerNameHash: new OctetString(await singleResponse.issuer.subjectName.getThumbprint(crypto)),
          issuerKeyHash: new OctetString(await singleResponse.issuer.publicKey.getKeyIdentifier(crypto)),
          serialNumber: Convert.FromHex(singleResponse.certificate.serialNumber)
        }),
        certStatus: new ocsp.CertStatus(singleResponse.status),
        thisUpdate: singleResponse.thisUpdate,
        // nextUpdate is optional
        ...(singleResponse.nextUpdate ? { nextUpdate: singleResponse.nextUpdate } : {})
      });
      responses.push(response);
    }

    // Parse responder to see if the responder ID is passed as name or key hash
    let responderID: ocsp.ResponderID;
    if (params.responder instanceof Name) {
      const name = params.responder.toArrayBuffer();
      responderID = new ocsp.ResponderID({ byName: AsnConvert.parse(name, asn1X509.Name) });
    } else {
      // Convert public key to CryptoKey
      const responderKey = params.responder;
      let publicKey: CryptoKey;
      let keyAlgorithm: Algorithm;
      if ("publicKey" in responderKey) {
        // IPublicKeyContainer
        keyAlgorithm = { ...responderKey.publicKey.algorithm};
        publicKey = await responderKey.publicKey.export(keyAlgorithm, ["verify"], crypto);
      } else if (responderKey instanceof PublicKey) {
        // PublicKey
        keyAlgorithm = { ...responderKey.algorithm};
        publicKey = await responderKey.export(keyAlgorithm, ["verify"], crypto);
      } else if (BufferSourceConverter.isBufferSource(responderKey)) {
        const key = new PublicKey(responderKey);
        keyAlgorithm = { ...key.algorithm};
        publicKey = await key.export(keyAlgorithm, ["verify"], crypto);
      } else {
        // CryptoKey
        keyAlgorithm = { ...responderKey.algorithm};
        publicKey = responderKey;
      }
      const spki = await crypto.subtle.exportKey("spki", publicKey);
      const asnPubKey = new PublicKey(AsnConvert.parse(spki, asn1X509.SubjectPublicKeyInfo));
      responderID = new ocsp.ResponderID({ byKey: new OctetString(await asnPubKey.getKeyIdentifier(crypto)) });
    }
    // construct tbsResponseData and get signature using signing key
    const tbsResponseData = new ocsp.ResponseData({
      version: ocsp.Version.v1,
      responderID: responderID,
      producedAt: params.date || new Date(),
      responses,
      responseExtensions: new asn1X509.Extensions(params.extensions?.map(o => AsnConvert.parse(o.rawData, asn1X509.Extension)) || [])
    });

    const tbs = AsnConvert.serialize(tbsResponseData);
    let signingAlgorithm = typeof(params.signatureAlgorithm) === "string" ? {name: params.signatureAlgorithm} : params.signatureAlgorithm;
    signingAlgorithm = {...signingAlgorithm, ...params.signingKey.algorithm};

    const signatureValue = await crypto.subtle.sign(signingAlgorithm, params.signingKey, tbs);
    // Convert WebCrypto signature to ASN.1 format
    const signatureFormatters = container.resolveAll<IAsnSignatureFormatter>(diAsnSignatureFormatter).reverse();
    let asnSignature: ArrayBuffer | null = null;
    for (const signatureFormatter of signatureFormatters) {
      asnSignature = signatureFormatter.toAsnSignature(signingAlgorithm as HashedAlgorithm, signatureValue);
      if (asnSignature) {
        break;
      }
    }
    if (!asnSignature) {
      throw Error("Cannot convert ASN.1 signature value to WebCrypto format");
    }

    const basicOCSPResp = new ocsp.BasicOCSPResponse({
      tbsResponseData: tbsResponseData,
      signature: asnSignature,
      signatureAlgorithm: algProv.toAsnAlgorithm(signingAlgorithm)
    });

    // append cert to the response
    if(params.certificates) {
      basicOCSPResp.certs = [];
      for(const certificate of params.certificates){
        const ans1Cert = AsnConvert.parse(certificate.rawData, asn1X509.Certificate);
        basicOCSPResp.certs.push(ans1Cert);
      }
    }

    const asnOcspResponse = new ocsp.OCSPResponse({
      responseStatus: params.status || OCSPResponseStatus.successful,
      responseBytes: new ocsp.ResponseBytes({
        responseType: ocsp.id_pkix_ocsp_basic,
        response: new OctetString(AsnConvert.serialize(basicOCSPResp))
      })
    });

    return new OCSPResponse(asnOcspResponse);
  }
}