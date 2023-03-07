import { ChainValidatorItem } from "../rule_validate/chain_validate";
import { ChainRule, ChainRuleType } from "../rule_validate/rule_registry";
import { ChainRuleValidateParams } from "../rule_validate/chain_validate";
import { recordingCertificateVerificationResults } from "./cyclic_rule";

export class ExpiredRule implements ChainRule {

  public id: string = "";
  public type: ChainRuleType = "critical";

  public async validate(params: ChainRuleValidateParams): Promise<ChainValidatorItem[]> {
    let verifiedCertificates: ChainValidatorItem[] = [];
    for (const chainCert of params.chain) {
      if (chainCert.notAfter.getTime() < params.checkDate.getTime()) {
        recordingCertificateVerificationResults(chainCert, { status: false, details: "The certificate is expired" }, verifiedCertificates);
      }
      if (chainCert.notBefore.getTime() > params.checkDate.getTime()) {
        recordingCertificateVerificationResults(chainCert, { status: false, details: "The certificate is not valid" }, verifiedCertificates);
      }
    }

    return verifiedCertificates;
  }
}