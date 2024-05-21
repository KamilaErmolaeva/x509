import { ICertificateStorage, ICertificateStorageHandler } from "./certificate_storage_handler";
import { DefaultCertificateStorageHandler } from "./default_certificate_storage_handler";
import { cryptoProvider } from "./provider";
import { X509Certificate } from "./x509_cert";
import { Convert } from "pvtsutils";
import {ChainRuleValidateResult} from "./x509_chain_validator";
import { SubjectKeyIdentifierExtension } from "./extensions";
import * as asn1X509 from "@peculiar/asn1-x509";


type IX509CertificateNodeState = "valid" | "invalid" | "unknown";

export interface IX509CertificateNode {
  certificate: X509Certificate;
  nodes: IX509CertificateNode[];
  state: IX509CertificateNodeState;
  rulesResults: ChainRuleValidateResult[];
}

type CertificateThumbprint = string;

type X509ChainNodeStorage = Record<CertificateThumbprint, IX509CertificateNode>;

export class X509CertificateTree implements ICertificateStorage {
  public certificateStorage: ICertificateStorageHandler = new DefaultCertificateStorageHandler();
  public chainNodeStorage: X509ChainNodeStorage = {};
  public cyclicality = false;

  /**
   * Returns the node of the certificate
   */
  public createNode(cert: X509Certificate): IX509CertificateNode {
    return { certificate: cert, nodes: [], rulesResults: [], state: "unknown" };
  }

  /**
   * Returns a filled node
   * @param certificatesTree Certificates tree
   * @param lastCert Issued certificate
   * @param parentCert Issuer certificates
   * @param crypto Crypto provider. Default is from CryptoProvider
   * @returns certificates tree
   */
  public async fillNode(certificatesTree: IX509CertificateNode, lastCert: X509Certificate, parentCert: X509Certificate, crypto = cryptoProvider.get()) {
    const thumbprint2 = Convert.ToHex(await parentCert.getThumbprint(crypto));
    if (certificatesTree.certificate.equal(lastCert)) {
      if (this.chainNodeStorage && !(thumbprint2 in this.chainNodeStorage)) {
        certificatesTree.nodes.push(this.createNode(parentCert));
      } else {
        if (!certificatesTree.nodes.some(item => item.certificate.equal(parentCert))) {
          certificatesTree.nodes.push(this.createNode(parentCert));
        } else {
          this.cyclicality = true;
        }
      }
    } else {
      certificatesTree.nodes.forEach(async (item) => {
        await this.fillNode(item, lastCert, parentCert);
      });
    }
  }


  /**
   * Returns part of the constructed certificate tree
   * @param cert Issued certificate
   * @param crypto Crypto provider. Default is from CryptoProvider
   * @returns certificates tree
   */
  async #build(cert: X509Certificate, certificatesTree: IX509CertificateNode, crypto = cryptoProvider.get()): Promise<IX509CertificateNode> {
    const thumbprint = Convert.ToHex(await cert.getThumbprint(crypto));
    if (this.chainNodeStorage && !(thumbprint in this.chainNodeStorage) || !this.chainNodeStorage) {
      this.chainNodeStorage = { [thumbprint]: this.createNode(cert), ...this.chainNodeStorage };
    }

    if (await cert.isSelfSigned(crypto)) {
      this.cyclicality = false;

      return certificatesTree;
    }

    const lastCerts = await this.certificateStorage.findIssuers(cert, crypto);

    if (lastCerts) {
      for (let i = 0; i < lastCerts.length; i++) {
        await this.fillNode(certificatesTree, cert, lastCerts[i]);
        if (!this.chainNodeStorage[thumbprint].nodes.some(item => lastCerts && item.certificate.equal(lastCerts[i]))) {
          this.chainNodeStorage[thumbprint].nodes.push(this.createNode(lastCerts[i]));
        }
        if (this.cyclicality) {
          this.cyclicality = false;

          continue;
        }
        await this.#build(lastCerts[i], certificatesTree);
      }
    }

    return certificatesTree;
  }

  public async build(cert: X509Certificate): Promise<IX509CertificateNode> {
    return await this.#build(cert, this.createNode(cert));
  }

  /**
   *Find the node containing the certificate by its ID and append the information in the node
   * @param node node of the certificate tree
   * @param serialNumber certificate serial number
   * @param rulesResults return of the rule check, to be appended to the certificate in the node
   */
  public async appendNodeData(cert: X509Certificate, rulesResults: ChainRuleValidateResult) :Promise<boolean>{
    const node = this.chainNodeStorage[Convert.ToHex(await cert.getThumbprint(crypto))];
    node.rulesResults.push(rulesResults);
    if(!rulesResults.status){
      node.state = "invalid";
    }

    return true;
  }

  /**
   * Find the certificate in the storage
   * @param responderID responderID, if string then it is a name, if ArrayBuffer then it is a keyHash
   */
  public findCertificate(responderID: string | ArrayBuffer): X509Certificate | undefined {

      return this.certificateStorage.findCertificate(responderID);
  }

  public getRulesData(node: IX509CertificateNode, serial: string): ChainRuleValidateResult[] {
    // check if the first certificate has the correct id
    if (node.certificate.serialNumber === serial){
      return node.rulesResults;
    }else{
      // recursively call the function to find the certificate in the tree
      if (node.nodes.length > 0){
        for(node of node.nodes){
          const result = this.getRulesData(node, serial);
          if (result.length > 0){
            return result;
          }
        }
      }
    }
    // if the certificate is not found in the tree return empty array

    return [];
  }
}