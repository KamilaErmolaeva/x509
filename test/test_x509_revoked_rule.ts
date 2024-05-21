import { assert } from "console";
import * as x509 from "../src";
import {OCSPResponseGenerator} from "../src/ocsp";
import { NonceExtension } from "../src/extensions";
import { Crypto } from "@peculiar/webcrypto";


const crypto = new Crypto();
x509.cryptoProvider.set(crypto);

const alg = {
    name: "ECDSA",
    hash: "SHA-1",
    namedCurve: "P-256",
};

const CAIssuerVector = {
  serialNumber: "01",
  name: "CN=CA1, O=Дом",
  subject: "CN=CA1, O=Дом",
  issuer: "CN=Root, O=Дом",
  notBefore: new Date(Date.UTC(2020, 0, 1, 8, 0, 0)), // UTCTime 2020-01-01 08:00:00 UTC
  notAfter: new Date(Date.UTC(2040, 0, 2, 8, 0, 0)),  // UTCTime 2040-01-02 08:00:00 UTC
  signingAlgorithm: alg,
  extensions: [
    new x509.BasicConstraintsExtension(true, 2, true),
    new x509.ExtendedKeyUsageExtension(["1.2.3.4.5.6.7", "2.3.4.5.6.7.8"], true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    new x509.CertificatePolicyExtension([
      "1.2.3.4.5",
      "1.2.3.4.5.6",
      "1.2.3.4.5.6.7",
    ]),
  ]
};

const rootVector = {
  serialNumber: "00",
  name: "CN=Root, O=Дом",
  subject: "CN=Root, O=Дом",
  issuer: "CN=Root, O=Дом",
  notBefore: new Date(Date.UTC(2020, 0, 1, 8, 0, 0)), // UTCTime 2020-01-01 08:00:00 UTC
  notAfter: new Date(Date.UTC(2040, 0, 2, 8, 0, 0)),  // UTCTime 2040-01-02 08:00:00 UTC
  signingAlgorithm: alg,
  extensions: [
    new x509.BasicConstraintsExtension(true, 2, true),
    new x509.ExtendedKeyUsageExtension(["1.2.3.4.5.6.7", "2.3.4.5.6.7.8"], true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    new x509.CertificatePolicyExtension([
      "1.2.3.4.5",
      "1.2.3.4.5.6",
      "1.2.3.4.5.6.7",
    ]),
  ]
};

const ocspRootVector = {
  serialNumber: "10",
  name: "CN=OCSPRoot, O=Дом",
  subject: "CN=OCSPRoot, O=Дом",
  issuer: "CN=OCSPRoot, O=Дом",
  notBefore: new Date(Date.UTC(2020, 0, 1, 8, 0, 0)), // UTCTime 2020-01-01 08:00:00 UTC
  notAfter: new Date(Date.UTC(2040, 0, 2, 8, 0, 0)),  // UTCTime 2040-01-02 08:00:00 UTC
  signingAlgorithm: alg,
  extensions: [
    new x509.BasicConstraintsExtension(true, 2, true),
    new x509.ExtendedKeyUsageExtension(["1.2.3.4.5.6.7", "2.3.4.5.6.7.8"], true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    new x509.CertificatePolicyExtension([
      "1.2.3.4.5",
      "1.2.3.4.5.6",
      "1.2.3.4.5.6.7",
    ]),
  ]
};

const LeafVector = {
  serialNumber: "02",
  name: "CN=Test, O=Дом",
  subject: "CN=Test, O=Дом",
  issuer: "CN=CA1, O=Дом",
  notBefore: new Date(Date.UTC(2020, 0, 1, 8, 0, 0)), // UTCTime 2020-01-01 08:00:00 UTC
  notAfter: new Date(Date.UTC(2040, 0, 2, 8, 0, 0)),  // UTCTime 2040-01-02 08:00:00 UTC
  signingAlgorithm: alg,
  extensions: [
    new x509.BasicConstraintsExtension(true, 2, true),
    new x509.ExtendedKeyUsageExtension(["1.2.3.4.5.6.7", "2.3.4.5.6.7.8"], true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    new x509.CertificatePolicyExtension([
      "1.2.3.4.5",
      "1.2.3.4.5.6",
      "1.2.3.4.5.6.7",
    ]),
  ]
};

context("OCSP", () => {
  it("Verify certificate", async () => {

    // get ocsp response for the leaf certificate

    const keysRoot = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
    const keysOCSPRoot = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
    const keysCA = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
    const keysLeaf = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);

    // const keysCA = {
    //   publicKey: await crypto.subtle.importKey("spki", Buffer.from(caPublicKey, "base64"), alg, true, ["verify"]),
    //   privateKey: await crypto.subtle.importKey("pkcs8", Buffer.from(caPrivateKey, "base64"), alg, true, ["sign"]),
    // };

    // const keysLeaf = {
    //   publicKey: await crypto.subtle.importKey("spki", Buffer.from(leafPublicKey, "base64"), alg, true, ["verify"]),
    //   privateKey: await crypto.subtle.importKey("pkcs8", Buffer.from(leafPrivateKey, "base64"), alg, true, ["sign"]),
    // };

    // assert(keysCA.publicKey);
    // assert(keysCA.privateKey);
    //
    const root = await x509.X509CertificateGenerator.createSelfSigned({
      keys: keysRoot,

      ...rootVector,
    });
    const ocspRoot = await x509.X509CertificateGenerator.createSelfSigned({
      keys: keysOCSPRoot,

      ...ocspRootVector,
    });
    const CACert = await x509.X509CertificateGenerator.create({
      publicKey: keysCA.publicKey,
      signingKey: keysRoot.privateKey,


      ...CAIssuerVector,
    });
    const leafCert = await x509.X509CertificateGenerator.create({
      publicKey: keysLeaf.publicKey,
      signingKey: keysCA.privateKey,


      ...LeafVector,
    });

    const leafCAResponse = await OCSPResponseGenerator.create({
      signatureAlgorithm: "SHA-1",
      signingKey: keysOCSPRoot.privateKey,
      singleResponses: [{
        issuer: CACert,
        certificate: leafCert,
        thisUpdate: new Date(Date.UTC(2024, 0, 1, 8, 0, 0)),
        nextUpdate: new Date(Date.UTC(2025, 0, 1, 8, 0, 0)),
        extensions : [],
        status: {good :null},
      }],
      responder: ocspRoot.subjectName,
      certificates: [ocspRoot],
      date: new Date(Date.UTC(2020, 0, 1, 8, 0, 0)),
      status: 0,
      extensions: [new NonceExtension(new TextEncoder().encode("Test Nonce"))],
    });
    const caRootResponse = await OCSPResponseGenerator.create({
      signatureAlgorithm: "SHA-1",
      signingKey: keysOCSPRoot.privateKey,
      singleResponses: [{
        issuer: root,
        certificate: CACert,
        thisUpdate: new Date(Date.UTC(2024, 0, 1, 8, 0, 0)),
        nextUpdate: new Date(Date.UTC(2025, 0, 1, 8, 0, 0)),
        extensions : [],
        status: {good :null},
      }],
      responder: ocspRoot.subjectName,
      certificates: [ocspRoot],
      date: new Date(Date.UTC(2020, 0, 1, 8, 0, 0)),
      status: 0,
      extensions: [new NonceExtension(new TextEncoder().encode("Test Nonce"))],
    });

    // parse certificates into a tree
    const certsTree = new x509.X509Certificates();
    certsTree.push(leafCert);
    certsTree.push(CACert);
    certsTree.push(root);
    certsTree.push(ocspRoot);

    // create a validator and run the revoked rule on the tree.
    const validator = new x509.X509ChainValidator();
    validator.rules.clear();
    validator.rules.add(new x509.rules.RevokedRule());
    validator.certificateStorage.certificates = certsTree;
    validator.certificateStorage.ocsp = [leafCAResponse, caRootResponse];
    // parse results
    const result = await validator.validate(certsTree[0]);
    assert(result.status === true);
  });
});