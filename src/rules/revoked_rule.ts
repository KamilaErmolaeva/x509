import { ChainRuleValidateParams, ChainRuleValidateResult } from "../x509_chain_validator";
import { ChainRule, ChainRuleType } from "./rule_registry";
import {X509CertificateTree}  from "../x509_certificate_tree";
import { OCSPWorker } from "../ocsp";
import { rules } from "..";


/**
 * Revoked Rule
 * This rule checks the if the certificate is revoked by the issuer
 */
export class RevokedRule implements ChainRule {

  public id = "revoked";
  public type = ChainRuleType.critical;

  public async validate(params: ChainRuleValidateParams): Promise<ChainRuleValidateResult> {
    const certificate = params.cert;
    const X509Chain = new X509CertificateTree();
    const node = params.node;
    // check if the certificate is self-signed
    // if it is self-signed, no further checks are made, assuming that the certificate is trusted
    // TODO: check if in trusted list or is self signed
    if(await certificate.isSelfSigned()){
      const result = { code: this.id, type: this.type,  status: true, details: "The certificate is self-signed" }
      X509Chain.appendNodeData(node, certificate.serialNumber, result);

      return result;
    }else{
      // find the ocsp response for the certificate
      const OCSPresponse = await params.storage.findOCSP(certificate);
      if(OCSPresponse.result === null){
        const result = { code: this.id, type: this.type, status: false, details: "OCSP response not found" };
        X509Chain.appendNodeData(node, certificate.serialNumber, result);

        return result;
      }else{
        // find the single response for the certificate
        if(OCSPresponse.result.basicResponse === null){
          const result = { code: this.id, type: this.type, status: false, details: "OCSP response is malformed" };
          X509Chain.appendNodeData(node, certificate.serialNumber, result);

          return result;
        }else{
          const singleResponse = OCSPresponse.result.basicResponse.responses.find(response => response.certificateID.serialNumber === certificate.serialNumber);
          if(singleResponse === undefined){
            const result = { code: this.id, type: this.type, status: false, details: "OCSP response not found" };
            X509Chain.appendNodeData(node, certificate.serialNumber, result);

            return result;
          }else{
            // check if the certificate is revoked
            if(singleResponse.status != true){
              const result = { code: this.id, type: this.type, status: false, details: "The certificate is revoked" };
              X509Chain.appendNodeData(node, certificate.serialNumber, result);

              return result;
            }else{
              // if the certificate is not revoked, check the OCSP provider certificate
              const responderID = OCSPresponse.result.basicResponse.responderID;
              if (responderID === undefined){
                const result = { code: this.id, type: this.type, status: false, details: "Failed to find responderID in OCSP response" };
                X509Chain.appendNodeData(node, certificate.serialNumber, result);

                return result;
              }else{
                const responderCert = X509Chain.findCertificateByResponderID(responderID, node);
                // TODO: if the responder certificate is not found, get it from the OCSP provider
                if(responderCert === undefined){
                  const result = { code: this.id, type: this.type, status: false, details: "Failed to find OCSP provider certificate" };
                  X509Chain.appendNodeData(node, certificate.serialNumber, result);

                  return result;
                }else{
                  // check if the responder certificate is trusted
                  const rulesResults = X509Chain.getRulesData(node, responderCert.serialNumber);
                  if(rulesResults.length > 0){
                    // check if every status in the rulesResults are true
                    const responderStatus = rulesResults.every(result => result.status === true);
                    if(responderStatus){
                      const result = { code: this.id, type: this.type, status: true, details: "The certificate is not revoked" };
                      X509Chain.appendNodeData(node, certificate.serialNumber, result);

                      return result;
                    }else{
                      const result = { code: this.id, type: this.type, status: false, details: "The OCSP provider certificate is not trusted" };
                      X509Chain.appendNodeData(node, certificate.serialNumber, result);

                      return result;
                    }
                  }
                  const result = { code: this.id, type: this.type, status: false, details: "The certificate is revoked" };
                  X509Chain.appendNodeData(node, certificate.serialNumber, result);

                  return result;
                }
              }
            }
          }
        }
      }
    }
  }
}