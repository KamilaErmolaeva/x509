import * as assert from "assert";
import * as x509 from "../src";
import { Crypto } from "@peculiar/webcrypto";
import { IX509CertificateNode } from "../src";

const crypto = new Crypto();
x509.cryptoProvider.set(crypto);

context("certificate tree", async () => {
  const certsTree = new x509.X509Certificates();



  before(async () => {
    const pems = [
      `-----BEGIN CERTIFICATE-----
MIIBkzCCATmgAwIBAgIUf4+73DZ7XINGZAmaGXQ5GXqFLL8wCgYIKoZIzj0EAwIw
JjEVMBMGA1UEAxMMUm9vdCBDQSBjZXJ0MQ0wCwYDVQQKEwRUZXN0MB4XDTIyMTEx
MDE0MjcwMloXDTQyMTExMDE0MjcwMlowJjEVMBMGA1UEAxMMUm9vdCBDQSBjZXJ0
MQ0wCwYDVQQKEwRUZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFSUGUvfS
b2fEzYGZGzef6DNSyl8RT/nUMboKsjEhKtPqJJE0+co34DqMj+2fQXqANJ0qhLmM
D/NvcZrEoqzMF6NFMEMwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8C
AQEwHQYDVR0OBBYEFDfuCmXrOZlOHg72EVaSNAJ6VDgkMAoGCCqGSM49BAMCA0gA
MEUCIQDu5DtWNJ0G4F7ER26wd/enFzeYQX4P0NTCIw91dUf6XQIgMDgwbl92xsg4
8cRBp6/p2q6ajJswsjVn7plpEL2sJ4o=
-----END CERTIFICATE-----`,
      `-----BEGIN CERTIFICATE-----
MIICajCCAhGgAwIBAgIUfxf9jyFqz9FAGKfrJyvc9DCbvF4wCgYIKoZIzj0EAwIw
JjEVMBMGA1UEAxMMUm9vdCBDQSBjZXJ0MQ0wCwYDVQQKEwRUZXN0MB4XDTIyMTEx
MDE0MjcwMloXDTMzMTExMDE0MjcwMlowLjEdMBsGA1UEAxMUSW50ZXJtZWRpYXRl
IENBIGNlcnQxDTALBgNVBAoTBFRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AATbkHNu+8Co/+TSG0Pufs/HEs5SELP39OCzKovPbUYSA8IHJF95Rh+wfPcOcLMk
b/r5Nb9WigwrJNosmdApaNbfo4IBEzCCAQ8wDgYDVR0PAQH/BAQDAgEGMBIGA1Ud
EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFPu3XMGqhbPRsLmHqguYSBura+VTMB8G
A1UdIwQYMBaAFDfuCmXrOZlOHg72EVaSNAJ6VDgkMDQGA1UdJQQtMCsGCCsGAQUF
BwMCBggrBgEFBQcDBAYKKwYBBAGCNwoDDAYJYIZIAYb6aygLMD4GCCsGAQUFBwEB
BDIwMDAuBggrBgEFBQcwAoYiaHR0cHM6Ly9sb2NhbGhvc3Q6ODAwMC9yb290LWNh
LmNlcjAzBgNVHR8ELDAqMCigJqAkhiJodHRwczovL2xvY2FsaG9zdDo4MDAwL3Jv
b3QtY2EuY3JsMAoGCCqGSM49BAMCA0cAMEQCIB/aVaEfcl/imQl6ypPWgoLXYfbV
U5ylPgI/7Fb1odLrAiAagmlhWDnlBvn3a76/cvVth2Oelkqk/4JKFeUPUCUTxg==
-----END CERTIFICATE-----`,
      `-----BEGIN CERTIFICATE-----
MIICbDCCAhGgAwIBAgIUfybbaXiv9H7CYMYWW1mUvgWmV+4wCgYIKoZIzj0EAwIw
JjEVMBMGA1UEAxMMUm9vdCBDQSBjZXJ0MQ0wCwYDVQQKEwRUZXN0MB4XDTIyMTEx
MDE0MjcwMloXDTMyMTExMDE0MjcwMlowLjEdMBsGA1UEAxMUSW50ZXJtZWRpYXRl
IENBIGNlcnQxDTALBgNVBAoTBFRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AATbkHNu+8Co/+TSG0Pufs/HEs5SELP39OCzKovPbUYSA8IHJF95Rh+wfPcOcLMk
b/r5Nb9WigwrJNosmdApaNbfo4IBEzCCAQ8wDgYDVR0PAQH/BAQDAgEGMBIGA1Ud
EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFPu3XMGqhbPRsLmHqguYSBura+VTMB8G
A1UdIwQYMBaAFDfuCmXrOZlOHg72EVaSNAJ6VDgkMDQGA1UdJQQtMCsGCCsGAQUF
BwMCBggrBgEFBQcDBAYKKwYBBAGCNwoDDAYJYIZIAYb6aygLMD4GCCsGAQUFBwEB
BDIwMDAuBggrBgEFBQcwAoYiaHR0cHM6Ly9sb2NhbGhvc3Q6ODAwMC9yb290LWNh
LmNlcjAzBgNVHR8ELDAqMCigJqAkhiJodHRwczovL2xvY2FsaG9zdDo4MDAwL3Jv
b3QtY2EuY3JsMAoGCCqGSM49BAMCA0kAMEYCIQCO29JPQZnI2Zl2LHrk2e2ors0P
JpHjMVG8z/OMc8/+CAIhAPlHevhcXkkXC916ecWtAutDKIUocuEaPuMJ8FmfAFTU
-----END CERTIFICATE-----`,
      `-----BEGIN CERTIFICATE-----
MIICdTCCAhugAwIBAgIUf46Govrsp6KQMmMz6ZEtI966zVcwCgYIKoZIzj0EAwIw
LjEdMBsGA1UEAxMUSW50ZXJtZWRpYXRlIENBIGNlcnQxDTALBgNVBAoTBFRlc3Qw
HhcNMjIxMTEwMTQyNzAyWhcNMzAxMTEwMTQyNzAyWjAwMR8wHQYDVQQDExZJbnRl
cm1lZGlhdGUgQ0EgY2VydCAyMQ0wCwYDVQQKEwRUZXN0MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAERck36R7bb2jGQD/SoLuuT3Mw6rE3zjTdJsd3YPgENefXrFfS
QQxIAUf0/A3YY9Tj/PlV1TPWI4oza10XJxeqB6OCARMwggEPMA4GA1UdDwEB/wQE
AwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTqLZChREZnbAaxxNOE
x6An1iEnvDAfBgNVHSMEGDAWgBT7t1zBqoWz0bC5h6oLmEgbq2vlUzA0BgNVHSUE
LTArBggrBgEFBQcDAgYIKwYBBQUHAwQGCisGAQQBgjcKAwwGCWCGSAGG+msoCzA+
BggrBgEFBQcBAQQyMDAwLgYIKwYBBQUHMAKGImh0dHBzOi8vbG9jYWxob3N0Ojgw
MDAvcm9vdC1jYS5jZXIwMwYDVR0fBCwwKjAooCagJIYiaHR0cHM6Ly9sb2NhbGhv
c3Q6ODAwMC9yb290LWNhLmNybDAKBggqhkjOPQQDAgNIADBFAiEAp141ilv+7ByT
tDOHbgNPnREiI9FXlQD3+Y5pAGejwe0CIFEftRX9exdNxTiuPniIzxW791L6ozMP
fZ+AyKJS7sqY
-----END CERTIFICATE-----`,
      `-----BEGIN CERTIFICATE-----
MIICdzCCAh2gAwIBAgIUf5YiNeKuyhTpfGeHcC2OA+3rpsIwCgYIKoZIzj0EAwIw
MDEfMB0GA1UEAxMWSW50ZXJtZWRpYXRlIENBIGNlcnQgMjENMAsGA1UEChMEVGVz
dDAeFw0yMjExMTAxNDI3MDJaFw0yOTExMTAxNDI3MDJaMDAxHzAdBgNVBAMTFklu
dGVybWVkaWF0ZSBDQSBjZXJ0IDQxDTALBgNVBAoTBFRlc3QwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAS86nBl9P3NwZ3AXyiieYgKaG86BAX3ABmx9nz889kd8utr
1JapN/FFVaRFu6Skw3E5r1YLdMJEC+RzWj1aH9HBo4IBEzCCAQ8wDgYDVR0PAQH/
BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFO/m2Xkhe9P6q0eq
BEhl403G1TlzMB8GA1UdIwQYMBaAFOotkKFERmdsBrHE04THoCfWISe8MDQGA1Ud
JQQtMCsGCCsGAQUFBwMCBggrBgEFBQcDBAYKKwYBBAGCNwoDDAYJYIZIAYb6aygL
MD4GCCsGAQUFBwEBBDIwMDAuBggrBgEFBQcwAoYiaHR0cHM6Ly9sb2NhbGhvc3Q6
ODAwMC9yb290LWNhLmNlcjAzBgNVHR8ELDAqMCigJqAkhiJodHRwczovL2xvY2Fs
aG9zdDo4MDAwL3Jvb3QtY2EuY3JsMAoGCCqGSM49BAMCA0gAMEUCICzC6uQwyfxz
KyxuCL+mDoY3P7lCeMm19dEUoK4+4sHnAiEAjoTfqv2pA4EGe9USSGgiYEhsa110
EQ+DQcSgMEnWzuc=
-----END CERTIFICATE-----`
    ];

    pems.forEach((pem) => certsTree.push(new x509.X509Certificate(pem)));
  });

  function walkingThroughTree(tree: IX509CertificateNode, certificateChain: Array<x509.X509Certificate>) {
    certificateChain.push(tree.certificate);
    if (tree.nodes.length !== 0) {
      tree.nodes.forEach(item => walkingThroughTree(item, certificateChain));
    }

    return certificateChain;
  }

  it("build chain tree", async () => {
    const chain = new x509.X509CertificateTree();
    chain.certificateStorage.certificates = certsTree;
    const certificateChain: x509.X509Certificate[] = [];
    const items = await chain.buildTree(certsTree[4]);
    const array = walkingThroughTree(items, certificateChain);
    assert.strictEqual(array.length, 6);
    assert.strictEqual(array.map(o => o.subject).join(","), "CN=Intermediate CA cert 4, O=Test,CN=Intermediate CA cert 2, O=Test,CN=Intermediate CA cert, O=Test,CN=Root CA cert, O=Test,CN=Intermediate CA cert, O=Test,CN=Root CA cert, O=Test");
  });

  it("self-signed certificate chain", async () => {
    const chain = new x509.X509CertificateTree();
    chain.certificateStorage.certificates = certsTree;
    const certificateChain: x509.X509Certificate[] = [];
    const items = await chain.buildTree(certsTree[0]);
    const array = walkingThroughTree(items, certificateChain);
    assert.strictEqual(array.length, 1);
    assert.strictEqual(array.map(o => o.subject).join(","), "CN=Root CA cert, O=Test");
  });

});