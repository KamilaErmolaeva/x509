import { isEqual } from "pvtsutils";
import { cryptoProvider } from "../provider";
import { ChainRuleValidateParams, ChainRuleValidateResult, ChainValidatorItem } from "../rule_validate/chain_validate";
import { ChainRule, ChainRuleType } from "../rule_validate/rule_registry";
import { X509Certificate } from "../x509_cert";

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

export class CyclicRule implements ChainRule {

  public id: string = "";
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