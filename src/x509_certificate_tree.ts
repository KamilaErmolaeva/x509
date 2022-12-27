import { ICertificateStorage, ICertificateStorageHandler } from "./certificate_storage_handler";
import { DefaultCertificateStorageHandler } from "./certificate_storage_handler";
import { cryptoProvider } from "./provider";
import { X509Certificate } from "./x509_cert";
import { Convert } from "pvtsutils";

type IX509CertificateNodeState = "valid" | "invalid" | "unknown";

export interface IX509CertificateNode {
  certificate: X509Certificate;
  nodes: IX509CertificateNode[];
  state: IX509CertificateNodeState;
}

type CertificateThumbprint = string;

type X509ChainNodeStorage = Record<CertificateThumbprint, IX509CertificateNode>;

export class X509CertificateTree implements ICertificateStorage {
  public certificateStorage: ICertificateStorageHandler = new DefaultCertificateStorageHandler();

  /**
   * Returns the node of the certificate
   */
  public createNode(cert: X509Certificate): IX509CertificateNode {
    return { certificate: cert, nodes: [], state: "unknown" };
  }

  /**
   * Returns a filled node
   * @param certificatesTree Certificates tree
   * @param lastCert Issued certificate
   * @param parentCert Issuer certificates
   * @param crypto Crypto provider. Default is from CryptoProvider
   * @returns certificates tree
   */
  public async fillNode(certificatesTree: IX509CertificateNode, lastCert: X509Certificate, parentCert: X509Certificate, chainNodeStorage: X509ChainNodeStorage, crypto = cryptoProvider.get()) {
    const thumbprint2 = Convert.ToHex(await parentCert.getThumbprint(crypto));
    if (certificatesTree.certificate.equal(lastCert)) {
      if (chainNodeStorage && !(thumbprint2 in chainNodeStorage)) {
        certificatesTree.nodes.push(this.createNode(parentCert));
      } else {
        if (!certificatesTree.nodes.some(item => { item.certificate.equal(parentCert); })) {
          certificatesTree.nodes.push(this.createNode(parentCert));
        }
      }
    } else {
      certificatesTree.nodes.forEach(item => {
        this.fillNode(item, lastCert, parentCert, chainNodeStorage);
      });
    }
  }


  /**
   * Returns part of the constructed certificate tree
   * @param cert Issued certificate
   * @param crypto Crypto provider. Default is from CryptoProvider
   * @returns certificates tree
   */
  async #build(cert: X509Certificate, chainNodeStorage: X509ChainNodeStorage, certificatesTree: IX509CertificateNode, crypto = cryptoProvider.get()): Promise<IX509CertificateNode> {
    const thumbprint = Convert.ToHex(await cert.getThumbprint(crypto));
    if (chainNodeStorage && !(thumbprint in chainNodeStorage) || !chainNodeStorage) {
      chainNodeStorage = { [thumbprint]: this.createNode(cert), ...chainNodeStorage };
    }

    if (await cert.isSelfSigned(crypto)) {
      return certificatesTree;
    }

    const lastCerts = await this.certificateStorage.findIssuers(cert, crypto);

    if (lastCerts) {
      for (let i = 0; i < lastCerts.length; i++) {
        this.fillNode(certificatesTree, cert, lastCerts[i], chainNodeStorage);
        if (!chainNodeStorage[thumbprint].nodes.some(item => { lastCerts && item.certificate.equal(lastCerts[i]); })) {
          chainNodeStorage[thumbprint].nodes.push(this.createNode(lastCerts[i]));
        }
        await this.#build(lastCerts[i], chainNodeStorage, certificatesTree);
      }
    }

    return certificatesTree;
  }

  public async buildTree(cert: X509Certificate): Promise<IX509CertificateNode> {
    return await this.#build(cert, {}, this.createNode(cert));
  }
}