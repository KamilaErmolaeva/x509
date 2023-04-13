import { X509Certificate } from "./x509_cert";
import { ICertificateStorageHandler } from "./certificate_storage_handler";
import { DefaultCertificateStorageHandler } from "./default_certificate_storage_handler";
import { IX509CertificateNode, X509CertificateTree } from "./x509_certificate_tree";
import { RuleRegistry, Rules } from "./rules/rule_registry";
import { CyclicRule } from "./rules/cyclic_rule";
import { ExpiredRule } from "./rules/expired_rule";
import { TrustedRule } from "./rules/trusted_rule";
import { X509Certificates } from "./x509_certs";
export interface ChainValidatorResult {
  status: boolean;
  items: ChainValidatorItem[];
}

export interface ChainValidatorItem {
  certificate: X509Certificate;
  results: ChainRuleValidateResult[];
  status: boolean;
}

export interface ChainRuleValidateParams {
  node: IX509CertificateNode;
  cert: X509Certificate;
  chain: X509Certificates;
  options: any;
  checkDate: Date;
}

export interface ChainRuleValidateResult {
  code: string;
  status: boolean;
  details: string;
}

export interface IX509ChainExpired {
  checkDate: Date;
}

export class X509ChainValidator {

  rules: RuleRegistry;
  certificateStorage: ICertificateStorageHandler = new DefaultCertificateStorageHandler();

  constructor() {
    this.rules = new RuleRegistry();
    this.rules.add(new CyclicRule());
    this.rules.add(new ExpiredRule());
    this.rules.add(new TrustedRule());
  }

  async validate(cert: X509Certificate): Promise<ChainValidatorResult> {
    const tree = new X509CertificateTree();
    const certificateChains = new X509ChainBuilderFromTree();
    tree.certificateStorage = this.certificateStorage;
    const treeRoot = await tree.build(cert);
    const chains = certificateChains.build(treeRoot);

    let result: ChainValidatorResult | undefined;


    for (const chain of chains) {
      result = await this.validateChain(chain, treeRoot);
      if (result.status) {
        return result;
      }
    }

    if (!result) {
      throw new Error("No chains to validate");
    }

    return result;
  }

  protected async validateChain(chain: X509Certificate[], treeRoot: IX509CertificateNode): Promise<ChainValidatorResult> {
    // вернуть ошибку если цепочка пустая
    if (chain.length === 0) {
      throw new Error("Chain is empty");
    }

    const res: ChainValidatorResult = {
      status: true,
      items: [],
    };

    // проверить цепочку используя RuleValidator
    const ruleValidator = new Rules(this.rules);

    for (let i = 0; i < chain.length; i++) {
      const cert = chain[i];

      const result = await ruleValidator.validates({
        node: treeRoot,
        cert,
        chain: chain as X509Certificates,
        options: "",
        checkDate: new Date(),
      });

      for (const item of result) {
        if (!item.status) {
          res.status = false;

          return res;
        }
      }
      res.items[0].results = result[0].results;
    }

    return res;
  }

}

/**
 * Builds all kinds of certificate chains from a tree
 */
export class X509ChainBuilderFromTree {
  public certificateChains: Array<X509Certificate>[] = [];
  public copyCertificateChain: X509Certificate[] = [];

  /**
   * Returns all possible certificate chains from the certificate tree
   * @param tree certificates tree
   * @returns certificate chains
   */
  #build(tree: IX509CertificateNode, certificateChain: Array<X509Certificate>) {
    certificateChain.push(tree.certificate);

    if (tree.nodes.length > 1) {
      this.copyCertificateChain = [...certificateChain];
    }

    if (!tree.nodes.length) {
      this.certificateChains.push(certificateChain);
    }

    for (let i = 0; i < tree.nodes.length; i++) {
      if (tree.nodes.length > 1) {
        certificateChain = [...this.copyCertificateChain];
        if (i === tree.nodes.length - 1) {
          this.copyCertificateChain.pop();
        }
      }
      this.#build(tree.nodes[i], certificateChain);
    }

    return this.certificateChains;
  }

  public build(tree: IX509CertificateNode) {

    return this.#build(tree, []);
  }
}