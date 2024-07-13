import * as asn1X509 from "@peculiar/asn1-x509";
import { AsnConvert } from "@peculiar/asn1-schema";
import { isEqual } from "pvtsutils";
import { X509Certificate } from "./x509_cert";
import { X509Certificates } from "./x509_certs";
import { cryptoProvider } from "./provider";
import { AuthorityKeyIdentifierExtension, SubjectKeyIdentifierExtension } from "./extensions";
import { ICertificateStorageHandler, IResult } from "./certificate_storage_handler";
import { X509Crl } from "./x509_crl";
import { OCSPResponse } from "./ocsp";
import { Convert } from "pvtsutils";


export class DefaultCertificateStorageHandler implements ICertificateStorageHandler {

  public parent: ICertificateStorageHandler | null = null;
  public certificates = new X509Certificates();
  public crls: X509Crl[] = [];

  public ocsp: OCSPResponse[] = [];
  public async findIssuers(cert: X509Certificate, crypto = cryptoProvider.get()): Promise<X509Certificates> {
    const issuerCerts: X509Certificates = new X509Certificates();
    if (this.parent) {
      return await this.parent.findIssuers(cert, crypto);
    }

    // Self-signed certificate
    if (await cert.isSelfSigned(crypto)) {
      issuerCerts.push(cert);
    } else {
      const akiExt = cert.getExtension<AuthorityKeyIdentifierExtension>(asn1X509.id_ce_authorityKeyIdentifier);
      for (const item of this.certificates) {
        if (item.subject !== cert.issuer) {
          continue;
        }

        if (akiExt) {
          if (akiExt.keyId) {
            const skiExt = item.getExtension<SubjectKeyIdentifierExtension>(asn1X509.id_ce_subjectKeyIdentifier);
            if (skiExt && skiExt.keyId !== akiExt.keyId) {
              continue;
            }
          } else if (akiExt.certId) {
            const sanExt = item.getExtension<SubjectKeyIdentifierExtension>(asn1X509.id_ce_subjectAltName);
            if (sanExt &&
              !(akiExt.certId.serialNumber === item.serialNumber && isEqual(AsnConvert.serialize(akiExt.certId.name), AsnConvert.serialize(sanExt)))) {
              continue;
            }
          }
        }
        if (!await cert.verify({
          publicKey: await item.publicKey.export(crypto),
          signatureOnly: true,
        }, crypto)) {
          continue;
        }

        issuerCerts.push(item);
      }
    }

    return issuerCerts;
  }

  public async isTrusted(cert: X509Certificate): Promise<IResult<boolean>> {
    if (this.parent) {
      const trusted = await this.parent.isTrusted(cert);
      if (trusted) {
        return trusted;
      }
    }

    return {
      target: this,
      result: false,
    };
  }

  /**
   *  Find the latest OCSP response for the certificate
   **/
  public async findOCSP(cert: X509Certificate, crypto = cryptoProvider.get()): Promise<IResult<OCSPResponse | null>> {
    const serialNumber = cert.serialNumber;

    const validResponses: OCSPResponse[] = [];

    if (this.ocsp.length === 0) {
      return {
        target: this,
        result: null,
      };
    }else{
      for (const ocsp of this.ocsp) {
        const singleResponses = ocsp.basicResponse?.responses;
        if (!singleResponses) {
          continue;
        }else{
          for(const singleResponse of singleResponses){
            let validity = true;
            if (!(singleResponse.certificateID.serialNumber === serialNumber)){
              validity = false;
            }
            const certIssuerNameHash = await cert.issuerName.getThumbprint(singleResponse.certificateID.hashAlgorithm, crypto);
            if (!isEqual(singleResponse.certificateID.issuerNameHash, certIssuerNameHash)) {
              validity = false;
            }
            if (validity){
              validResponses.push(ocsp);
            }
          }
        }
      }
      // if there are no valid responses return null
      // else return the latest response
      if (validResponses.length === 0){
        return {
          target: this,
          result: null,
        };
      }else{
          // sort the responses by the producedAt field
          validResponses.sort((a, b) => {
            if(!a.basicResponse || !b.basicResponse){
              return 0;
            }

            return a.basicResponse?.producedAt.getTime() - b.basicResponse?.producedAt.getTime();
          });
        }
    }

   return {
      target: this,
      result: validResponses[0],
    };
  }

  async findCertificate(responderID: string | ArrayBuffer): Promise<X509Certificate[] | null> {
    // generate array of certificates and fill it with the certificates from the storage
    const certificates: X509Certificate[] = [];


    if (typeof responderID === "string") {
      for (const cert of this.certificates) {
        if (cert.subject === responderID) {
          certificates.push(cert);
        }
      }
    } else {
      const keyId = Convert.ToHex(responderID);
      for (const cert of this.certificates) {
        const ski = cert.getExtension<SubjectKeyIdentifierExtension>(asn1X509.id_ce_subjectKeyIdentifier);
        if (!ski){
          const skiAlt = Convert.ToHex(await cert.publicKey.getKeyIdentifier());
          if (skiAlt === keyId){
            certificates.push(cert);
          }
        }
        if (ski && ski.keyId === keyId) {
          certificates.push(cert);
        }
      }
    }

    if(certificates.length > 0){
      return certificates;
    }

    return null;
  }
}