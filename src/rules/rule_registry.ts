import { ChainRuleValidateParams, ChainRuleValidateResult } from "../x509_chain_validator";

export type ChainRuleType = "critical" | "error" | "notice" | "warning";

export interface ChainRule {
  id: string;
  type: ChainRuleType;
  validate(params: ChainRuleValidateParams): Promise<ChainRuleValidateResult>;
}

export interface RuleValidatorResult {
  status: boolean;
  items: ChainRuleValidateResult[];
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
}

export class Rules {
  public registry: RuleRegistry = new RuleRegistry();

  constructor(registry: RuleRegistry) {
    this.registry = registry;
  }
  async validates(params: ChainRuleValidateParams): Promise<RuleValidatorResult> {
    const result: RuleValidatorResult = { items: [], status: true };

    for (let i = 0; i < this.registry.items.length; i++) {
      const item = await this.registry.items[i].validate(params);
      result.items.push(item);
      if (item.status === false) {
        result.status = false;

        // если проверка имеет тип "critical", то дальнейшая проверка не имеет смысла
        if (this.registry.items[i].type === "critical") {
          break;
        }
      }
    }

    return result;
  }
}