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
    for (let i = 0; i < params.chain.length; i++) {
      const thumbprint = await params.chain[i].getThumbprint(crypto);
      for (let j = i + 1; j < params.chain.length; j++) {
        const thumbprint2 = await params.chain[j].getThumbprint(crypto);
        if (isEqual(thumbprint, thumbprint2)) {
          return [{ certificate: params.chain[i], results: [{ status: false, details: "Circular dependency." }], status: false }];
        }
      }
    }

    return [{ certificate: params.cert, results: [{ status: true, details: "The certificate chain is valid" }], status: true }];
  }
}