import { assert } from "console";
import * as x509 from "../src";
import {OCSPResponseCreateParams} from "../src/ocsp";
import {OCSPResponseGenerator} from "../src/ocsp";
import {SingleResponseInterface} from "../src/ocsp";
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
  serialNumber: "00",
  name: "CN=CA, O=Дом",
  subject: "CN=CA, O=Дом",
  issuer: "CN=CA, O=Дом",
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
  serialNumber: "01",
  name: "CN=Test, O=Дом",
  subject: "CN=Test, O=Дом",
  issuer: "CN=CA, O=Дом",
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

const leafPrivateKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgM5McsRyvuC8+aFYwu2ci0Qh8bolc3kWCiF7F1WAQH1ahRANCAAS6zcN8ZmKsXlSR1FAPtooB6nGmsbNVNbkT2tNF6EDcAveJnd5xhNFtZ5dvPY6SR1Jjp/oytNlNFYXUrryrLfCJ";
const leafPublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEus3DfGZirF5UkdRQD7aKAepxprGzVTW5E9rTRehA3AL3iZ3ecYTRbWeXbz2OkkdSY6f6MrTZTRWF1K68qy3wiQ==";
const caPrivateKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgE/+gM0YVMwVMLEJZRlTnFHjQdA7PGlvx4RrwbNjWvEChRANCAAT9AozzW2pwptkjuponmuLdwEdnpTKNdrzQt0UxC7/GtA4rdy6xl9w8FtuN1rbeDo3b6EkYv/jtbsU3yL+0oQ1o";
const caPublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/QKM81tqcKbZI7qaJ5ri3cBHZ6UyjXa80LdFMQu/xrQOK3cusZfcPBbbjda23g6N2+hJGL/47W7FN8i/tKENaA==";


context("OCSP", () => {
  it("Verify certificate", async () => {

    // get ocsp response for the leaf certificate
    const keysCA = {
      publicKey: await crypto.subtle.importKey("spki", Buffer.from(caPublicKey, "base64"), alg, true, ["verify"]),
      privateKey: await crypto.subtle.importKey("pkcs8", Buffer.from(caPrivateKey, "base64"), alg, true, ["sign"]),
    };

    const keysLeaf = {
      publicKey: await crypto.subtle.importKey("spki", Buffer.from(leafPublicKey, "base64"), alg, true, ["verify"]),
      privateKey: await crypto.subtle.importKey("pkcs8", Buffer.from(leafPrivateKey, "base64"), alg, true, ["sign"]),
    };

    // assert(keysCA.publicKey);
    // assert(keysCA.privateKey);
    const CACert = await x509.X509CertificateGenerator.createSelfSigned({
      keys: keysCA,

      ...CAIssuerVector,
    });

    const leafCert = await x509.X509CertificateGenerator.create({
      publicKey: keysLeaf.publicKey,
      signingKey: keysCA.privateKey,


      ...LeafVector,
    });

    // create OCSPResponseCreateParams object and fill it with data
    const singleResponse: SingleResponseInterface ={
      issuer: CACert,
      certificate: leafCert,
      thisUpdate: new Date(Date.UTC(2024, 0, 1, 8, 0, 0)),
      nextUpdate: new Date(Date.UTC(2025, 0, 1, 8, 0, 0)),
      extensions : [],
      status: {good :null},
    };

    const ocspRequestParams: OCSPResponseCreateParams = {
      signatureAlgorithm: "SHA-1",
      signingKey: keysCA.privateKey,
      singleResponses: [singleResponse],
      responder: CACert.subjectName,
      certificates: [CACert],
      date: new Date(Date.UTC(2020, 0, 1, 8, 0, 0)),
      status: 0,
      extensions: [new NonceExtension(new TextEncoder().encode("Test Nonce"))],
    };

    const response = await OCSPResponseGenerator.create(ocspRequestParams);

    // parse certificates into a tree
    const certsTree = new x509.X509Certificates();
    certsTree.push(leafCert);
    certsTree.push(CACert);

    // create a validator and run the revoked rule on the tree.
    const validator = new x509.X509ChainValidator();
    validator.rules.clear();
    validator.rules.add(new x509.rules.RevokedRule());
    validator.certificateStorage.certificates = certsTree;
    validator.certificateStorage.ocsp = [response];

    // parse results
    const result = await validator.validate(certsTree[0]);
    assert(result.status === true);
  });
});