import { isEqual } from "pvtsutils";
import { cryptoProvider } from "../provider";
import { X509Certificate } from "../x509_cert";
import { ChainRuleValidateParams, ChainRuleValidateResult, ChainValidatorItem } from "../x509_chain_validator";

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

export class RuleRegistry {
  items: ChainRule[] = [];

  /**
   * Добавление правила валидации
   * @param rule правило валидации
   */
  add(rule: ChainRule): void {
    this.items.push(rule);
  }

  // get<T extends ChainRule>(type: new () => T): T;
}

export class Rules {
  public registry: RuleRegistry = new RuleRegistry();

  constructor(registry: RuleRegistry) {
    this.registry = registry;
  }
  async validates(params: ChainRuleValidateParams): Promise<ChainValidatorItem[]> {
    let result: ChainValidatorItem[] = [];
    for (const item of this.registry.items) {
      result = await item.validate(params);
    }

    return result;
  }
}