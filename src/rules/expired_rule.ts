import { ChainValidatorItem } from "../rule_validate/chain_validate";
import { ChainRule, ChainRuleType, recordingCertificateVerificationResults } from "../rule_validate/rule_registry";
import { ChainRuleValidateParams } from "../rule_validate/chain_validate";

/**
 * Expired Rule
 * This rule checks the validity period of certificates in the certificate chain
 */
export class ExpiredRule implements ChainRule {

  public id: string = "expired";
  public type: ChainRuleType = "critical";
  public verifiedCertificates: ChainValidatorItem[] = [];

  public async validate(params: ChainRuleValidateParams): Promise<ChainValidatorItem[]> {
    for (const chainCert of params.chain) {
      if (chainCert.notAfter.getTime() < params.checkDate.getTime()) {
        await recordingCertificateVerificationResults(chainCert, { status: false, details: "The certificate is expired" }, this.verifiedCertificates);
      } else if (chainCert.notBefore.getTime() > params.checkDate.getTime()) {
        await recordingCertificateVerificationResults(chainCert, { status: false, details: "The certificate is not yet valid" }, this.verifiedCertificates);
      } else {
        await recordingCertificateVerificationResults(chainCert, { status: true, details: "The certificate is valid" }, this.verifiedCertificates);
      }
    }

    return this.verifiedCertificates;
  }
}