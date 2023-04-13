import { ChainRuleValidateParams, ChainValidatorItem } from "../x509_chain_validator";
import { ChainRule, ChainRuleType, recordingCertificateVerificationResults } from "./rule_registry";

/**
 * Expired Rule
 * This rule checks the validity period of certificates in the certificate chain
 */
export class ExpiredRule implements ChainRule {

  public id = "expired";
  public type: ChainRuleType = "critical";
  public checkDate: Date = new Date();
  public verifiedCertificates: ChainValidatorItem[] = [];

  public async validate(params: ChainRuleValidateParams): Promise<ChainValidatorItem[]> {
    for (const chainCert of params.chain) {
      if (chainCert.notAfter.getTime() < params.checkDate.getTime()) {
        await recordingCertificateVerificationResults(chainCert, { code: this.id, status: false, details: "The certificate is expired" }, this.verifiedCertificates);
      } else if (chainCert.notBefore.getTime() > params.checkDate.getTime()) {
        await recordingCertificateVerificationResults(chainCert, { code: this.id, status: false, details: "The certificate is not yet valid" }, this.verifiedCertificates);
      } else {
        await recordingCertificateVerificationResults(chainCert, { code: this.id, status: true, details: "The certificate is valid" }, this.verifiedCertificates);
      }
    }

    return this.verifiedCertificates;
  }
}