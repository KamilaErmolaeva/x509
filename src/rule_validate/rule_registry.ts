import { isEqual } from "pvtsutils";
import { ChainRuleValidateParams, ChainRuleValidateResult, ChainValidatorItem } from "../rule_validate/chain_validate";
import { X509Certificate } from "../x509_cert";

export type ChainRuleType = "critical" | "error" | "notice" | "warning";

export interface ChainRule {
  id: string;
  type: ChainRuleType;
  validate(params: ChainRuleValidateParams): Promise<ChainValidatorItem[]>;
}

export function recordingCertificateVerificationResults(chainCert: X509Certificate, result: ChainRuleValidateResult, verifiedCertificates: ChainValidatorItem[]) {
  const desiredCertificate = verifiedCertificates.find(async (certInfo) => {
    const thumbprint = await certInfo.certificate.getThumbprint(crypto);
    const thumbprint2 = await chainCert.getThumbprint(crypto);
    isEqual(thumbprint, thumbprint2);
  });
  if (!!desiredCertificate) {
    desiredCertificate.results.push(result);
  } else {
    verifiedCertificates.push({ certificate: chainCert, results: [result], status: true });
  }
}

class RulesRegistry {
  public static items: ChainRule[];

  /**
   * Registers certificate chain validation rules
   * @param rule Rule of type ChainRule
   *
   * @example
   * ```js
   * RulesRegistry.register(cyclic);
   * ```
   */
  public static register(rule: ChainRule) {
    this.items.push(rule);
  }
}
export class Rules {
  validates() {
    RulesRegistry.items.forEach(o => o.validate);
  }
}
