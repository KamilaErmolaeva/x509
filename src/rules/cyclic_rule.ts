import { isEqual } from "pvtsutils";
import { cryptoProvider } from "../provider";
import { ChainRuleValidateParams, ChainValidatorItem } from "../rule_validate/chain_validate";
import { ChainRule, ChainRuleType } from "../rule_validate/rule_registry";

/**
 * Cyclic Rule
 * This rule checks the chain of certificates for cyclicity
 */
export class CyclicRule implements ChainRule {

  public id: string = "cyclic";
  public type: ChainRuleType = "critical";

  public async validate(params: ChainRuleValidateParams, crypto = cryptoProvider.get()): Promise<ChainValidatorItem[]> {
    for (const chainCert of params.chain) {
      const thumbprint = await chainCert.getThumbprint(crypto);
      for (const cert of params.chain) {
        const thumbprint2 = await cert.getThumbprint(crypto);
        if (isEqual(thumbprint, thumbprint2)) {
          return [{ certificate: chainCert, results: [{ status: false, details: "Circular dependency." }], status: false }];
        }
      }
    }

    return [{ certificate: params.cert, results: [{ status: true, details: "The certificate chain is valid" }], status: true }];
  }
}