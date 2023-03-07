import { DefaultCertificateStorageHandler } from "../default_certificate_storage_handler";
import { ChainValidatorItem } from "../rule_validate/chain_validate";
import { ChainRule, ChainRuleType } from "../rule_validate/rule_registry";
import { ChainRuleValidateParams } from "../rule_validate/chain_validate";
import { recordingCertificateVerificationResults } from "./cyclic_rule";

export class TrustedRule implements ChainRule {

  public id: string = "";
  public type: ChainRuleType = "critical";

  public async validate(params: ChainRuleValidateParams): Promise<ChainValidatorItem[]> {
    let verifiedCertificates: ChainValidatorItem[] = [];
    for (const chainCert of params.chain) {
      const trustedChain = await (params.chain as unknown as DefaultCertificateStorageHandler).isTrusted(chainCert);
      if (!trustedChain.result) {
        recordingCertificateVerificationResults(chainCert, { status: false, details: "Parent certificates are not included in trusted list" }, verifiedCertificates);
      } else {
        recordingCertificateVerificationResults(chainCert, { status: true, details: "Parent certificates are included in trusted list" }, verifiedCertificates);
      }
    }

    return verifiedCertificates;
  }
}