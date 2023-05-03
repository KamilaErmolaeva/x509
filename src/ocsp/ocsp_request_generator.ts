import * as ocsp from "@peculiar/asn1-ocsp";
import * as asn1X509 from "@peculiar/asn1-x509";
import { Extension } from "../extension";
import { GeneralName } from "../general_name";
import { X509Certificate } from "../x509_cert";
import { OCSPRequest } from "./ocsp_request";
import { container } from "tsyringe";
import { AlgorithmProvider, diAlgorithmProvider } from "../algorithm";
import { cryptoProvider } from "../provider";
import { IAsnSignatureFormatter, diAsnSignatureFormatter } from "../asn_signature_formatter";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { CertificateID } from "./cert_id";
import { HashedAlgorithm } from "../types";

export interface OCSPRequestCreateParams {
  /**
   * The name of the requestor
   */
  requestorName?: GeneralName;
  /**
   * The certificate for which the status is being requested
  */
  certificate: X509Certificate;
  /**
   * The certificate of the certificate issuer for which the status is being requested
   */
  issuer: X509Certificate;
  /**
   * Gets a list of request extensions
   */
  extensions?: Extension[];
  /**
   * The hashing algorithm identifier for signing the OCSP request
   * If not specified, no signature is required
   */
  signatureAlgorithm?: AlgorithmIdentifier;
  /**
   * OCSP request signing key
   * If not specified, no signature is required
   */
  signingKey?: CryptoKey;
}

export class OCSPRequestGenerator {
  /**
   * Generates an OCSP request
   * @param params OCSP Request Generation Options
   * @param crypto Crypto provider. Default is from CryptoProvider
   * @returns OCSP request
   */
  public static async create(params: OCSPRequestCreateParams, crypto = cryptoProvider.get()): Promise<OCSPRequest> {
    const certID = await CertificateID.create(params.certificate.publicKey.algorithm, params.issuer, params.certificate.serialNumber);
    const nonce = crypto.getRandomValues(new Uint8Array(20));

    const asnOcspReq = new ocsp.OCSPRequest({
      tbsRequest: new ocsp.TBSRequest({
        version: ocsp.Version.v1,
        requestExtensions: new asn1X509.Extensions(params.extensions?.map(o => AsnConvert.parse(o.rawData, asn1X509.Extension)) || []),
        requestList: [
          new ocsp.Request({
            reqCert: AsnConvert.parse(certID.rawData, ocsp.CertID),
            singleRequestExtensions: [
              new asn1X509.Extension({
                extnID: ocsp.id_pkix_ocsp_nonce,
                extnValue: new OctetString(nonce),
              })
            ]
          })
        ],
      })
    });

    if (params.requestorName) {
      asnOcspReq.tbsRequest.requestorName = params.requestorName as asn1X509.GeneralName;
    }

    const algProv = container.resolve<AlgorithmProvider>(diAlgorithmProvider);

    // Sign
    const tbs = AsnConvert.serialize(asnOcspReq.tbsRequest);

    if (params.signatureAlgorithm && params.signingKey) {
      const signatureValue = await crypto.subtle.sign(params.signatureAlgorithm, params.signingKey, tbs);

      // Convert WebCrypto signature to ASN.1 format
      const signatureFormatters = container.resolveAll<IAsnSignatureFormatter>(diAsnSignatureFormatter).reverse();
      let asnSignature: ArrayBuffer | null = null;
      for (const signatureFormatter of signatureFormatters) {
        asnSignature = signatureFormatter.toAsnSignature(params.signatureAlgorithm as HashedAlgorithm, signatureValue);
        if (asnSignature) {
          break;
        }
      }
      if (!asnSignature) {
        throw Error("Cannot convert ASN.1 signature value to WebCrypto format");
      }

      if (asnOcspReq.optionalSignature) {
        asnOcspReq.optionalSignature.signature = asnSignature;
        asnOcspReq.optionalSignature.signatureAlgorithm = algProv.toAsnAlgorithm(params.signatureAlgorithm as HashedAlgorithm);
      }
    }

    return new OCSPRequest(AsnConvert.serialize(asnOcspReq));
  }
}