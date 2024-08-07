import { Convert } from "pvtsutils";
import { X509CertificateTree } from "../x509_certificate_tree";
import { ChainRuleValidateParams, ChainRuleValidateResult } from "../x509_chain_validator";
import { ChainRule, ChainRuleType } from "./rule_registry";
import {X509ChainValidator} from "../x509_chain_validator";
import { X509Certificate } from "../x509_cert";

/**
 * Revoked Rule
 *
 * This rule checks if the certificate is revoked by the issuer
 */
export class RevokedRule implements ChainRule {
  public id = "revoked";
  public type = ChainRuleType.critical;

  public async validate(params: ChainRuleValidateParams): Promise<ChainRuleValidateResult> {
    const certificate = params.cert;
    const tree = params.tree;

    // Check if the certificate is self-signed
    if (await certificate.isSelfSigned()) {
      return await this.createResult(tree, certificate, true, "The certificate is self-signed");
    }

    // Find the OCSP response for the certificate
    const ocspResponse = await tree.certificateStorage.findOCSP(certificate);
    if (!ocspResponse.result?.basicResponse) {
      return await this.createResult(tree, certificate, false, "OCSP response not found");
    }

    // Find the single response for the certificate
    const singleResponse = ocspResponse.result.basicResponse.responses.find(
      (response) => response.certificateID.serialNumber === certificate.serialNumber
    );
    if (!singleResponse) {
      return await this.createResult(tree, certificate, false, "Single response not found");
    }
    if (singleResponse?.status !== true) {
      return await this.createResult(tree, certificate, false, "The certificate is revoked");
    }

    // If the certificate is not revoked, check the OCSP provider certificate
    const responderID = ocspResponse.result.basicResponse.responderID;
    if (!responderID) {
      return await this.createResult(tree, certificate, false, "Failed to find responderID in OCSP response");
    }

    // Try to find the responder certificate in the existing nodes
    // TODO: Implement OCSP certificate storage and use it here
    const responderCert = await tree.certificateStorage.findCertificate(responderID);
    if (responderCert.length === 0) {
      return await this.createResult(tree, certificate, false, "Failed to find OCSP provider certificate");
    }

    const responderNode = tree.chainNodeStorage[Convert.ToHex(await responderCert[0].getThumbprint())];
    // check if the responder certificate is in a node and has been checked
    // if it is has not been validated or it is not in a node, build the tree around the responder certificate
    // and call validate on that tree

    if(responderNode === undefined ||
       (!responderNode.rulesResults.every((result) => result.type !== this.id)  &&
        responderNode.state !== "invalid")){

      const validator = new X509ChainValidator();
      validator.rules.clear();
      validator.rules.add(new RevokedRule());
      const result = await validator.validate(responderCert[0], tree);
      if (result.status === false) {
        return await this.createResult(tree, certificate, false, "The OCSP provider certificate is not trusted");
      } else {
        return await this.createResult(tree, certificate, true, "The certificate is not revoked");
      }
    }

    const rulesResults = tree.getRulesData(responderNode, responderCert[0].serialNumber);

    if (rulesResults.length > 0) {
      const responderStatus = rulesResults.every((result) => result.status === true);

      if (responderStatus) {
        return await this.createResult(tree, certificate, true, "The certificate is not revoked");
      } else {
        return await this.createResult(tree, certificate, false, "The OCSP provider certificate is not trusted");
      }
    }


    return await this.createResult(tree, certificate, false, "The certificate is revoked");
  }

  private async createResult(tree: X509CertificateTree, certificate: X509Certificate, status: boolean, details: string): Promise<ChainRuleValidateResult> {
    const result = { code: this.id, type: this.type, status, details };
    const node = tree.chainNodeStorage[Convert.ToHex(await certificate.getThumbprint())];
    if(node){
      node.rulesResults.push(result);
      if(!result.status){
        node.state = "invalid";
      }

      return result;
    }else{
      return { code: this.id, type: this.type, status: false, details: "Failed to find the node in the tree" };
    }
  }
}