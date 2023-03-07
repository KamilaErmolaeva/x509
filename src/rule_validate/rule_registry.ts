import { ChainRuleValidateParams, ChainValidatorItem } from "../rule_validate/chain_validate";

export type ChainRuleType = "critical" | "error" | "notice" | "warning";

export interface ChainRule {
  id: string;
  type: ChainRuleType;
  validate(params: ChainRuleValidateParams): Promise<ChainValidatorItem[]>;
}

class RulesRegistry {
  public static items: ChainRule[];

  /**
   * Registers certificate chain validation rules
   * @param rule Rule of type ChainRule
   *
   * @example
   * ```js
   * RulesRegistry.register(CyclicValidate);
   * ```
   */
  public static register(rule: ChainRule) {
    this.items.push(rule);
  }
}
class Rules {
  validates() {
    RulesRegistry.items.forEach(o => o.validate);
  }
}
