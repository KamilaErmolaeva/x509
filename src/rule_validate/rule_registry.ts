import { ChainRuleValidateParams, ChainRuleValidateResult } from "./chain_rule_validate";

type ChainRuleType = "critical" | "error" | "notice" | "warning";

interface ChainRule {
  id: string;
  type: ChainRuleType;
  validate(params: ChainRuleValidateParams): Promise<ChainRuleValidateResult>;
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
class Rules implements RulesRegistry {
  validates() {
    RulesRegistry.items.forEach(o => o.validate);
  }
}
