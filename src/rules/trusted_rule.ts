import { ChainValidatorItem, ChainRuleValidateParams } from "../rule_validate/chain_validate";
import { ChainRule, ChainRuleType, recordingCertificateVerificationResults } from "../rule_validate/rule_registry";
import { X509CertificateTree } from "../x509_certificate_tree";

/**
 * Trusted Rule
 * This rule checks that parent certificates are included in the list of trusted certificates
 */
export class TrustedRule implements ChainRule {

  public id: string = "trusted";
  public type: ChainRuleType = "critical";
  public verifiedCertificates: ChainValidatorItem[] = [];

  public async validate(params: ChainRuleValidateParams): Promise<ChainValidatorItem[]> {
    const chain = new X509CertificateTree();
    chain.certificateStorage.certificates = params.chain;
    for (const chainCert of params.chain) {
      const trustedChain = await chain.certificateStorage.isTrusted(chainCert);
      if (!trustedChain.result) {
        await recordingCertificateVerificationResults(chainCert, { status: false, details: "Parent certificates are not included in trusted list" }, this.verifiedCertificates);
      } else {
        await recordingCertificateVerificationResults(chainCert, { status: true, details: "Parent certificates are included in trusted list" }, this.verifiedCertificates);
      }
    }

    return this.verifiedCertificates;
  }
}