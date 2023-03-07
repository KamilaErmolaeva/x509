import { X509Certificate } from "./x509_cert";
import { ICertificateStorage, ICertificateStorageHandler } from "./certificate_storage_handler";
import { DefaultCertificateStorageHandler } from "./default_certificate_storage_handler";
import { IX509CertificateNode } from "./x509_certificate_tree";

export class X509ChainValidator implements ICertificateStorage {
  public certificateStorage: ICertificateStorageHandler = new DefaultCertificateStorageHandler();

  // verify(certificate: X509Certificate);
}

export class X509ChainBuilderFromTree {
  public certificateChains: Array<X509Certificate>[] = [];
  public copyCertificateChain: X509Certificate[] = [];

  public buildChainCertificatesFromTree(tree: IX509CertificateNode, certificateChain: Array<X509Certificate>) {
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
      this.buildChainCertificatesFromTree(tree.nodes[i], certificateChain);
    }

    return this.certificateChains;
  }
}