import { Convert, isEqual } from "pvtsutils";
import { cryptoProvider } from "../provider";
import { ChainRuleValidateParams, ChainRuleValidateResult, ChainValidatorItem } from "../rule_validate/chain_validate";
import { X509Certificate } from "../x509_cert";

export type ChainRuleType = "critical" | "error" | "notice" | "warning";

export interface ChainRule {
  id: string;
  type: ChainRuleType;
  validate(params: ChainRuleValidateParams): Promise<ChainValidatorItem[]>;
}

export async function recordingCertificateVerificationResults(chainCert: X509Certificate, result: ChainRuleValidateResult, verifiedCertificates: ChainValidatorItem[], crypto = cryptoProvider.get()) {
  const arr = [];
  for (const certInfo of verifiedCertificates) {
    arr.push(isEqual(await certInfo.certificate.getThumbprint(crypto), await chainCert.getThumbprint(crypto)));
  }
  if (arr.includes(true)) {
    for (const certInfo of verifiedCertificates) {
      if (isEqual(await certInfo.certificate.getThumbprint(crypto), await chainCert.getThumbprint(crypto))) {
        certInfo.results.push(result);
      }
    }
  } else {
    verifiedCertificates.push({ certificate: chainCert, results: [result], status: true });
  }
}

export class RulesRegistry {
  public static items: ChainRule[] = [];

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
  public static async validates(params: ChainRuleValidateParams): Promise<ChainValidatorItem[][]> {
    let result: ChainValidatorItem[][] = [];
    for (const item of RulesRegistry.items) {
      result.push(await item.validate(params));
    }

    return result;
  }
}