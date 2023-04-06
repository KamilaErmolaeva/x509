import * as assert from "assert";
import * as x509 from "../src";
import { Crypto } from "@peculiar/webcrypto";
import { ChainRule, Rules, RulesRegistry } from "../src/rule_validate/rule_registry";
import { CyclicRule } from "../src/rules/cyclic_rule";
import { TrustedRule } from "../src/rules/trusted_rule";
import { ExpiredRule } from "../src/rules/expired_rule";
import { ChainRuleValidateParams } from "../src/rule_validate/chain_validate";

const crypto = new Crypto();
x509.cryptoProvider.set(crypto);

context("certificate tree", async () => {
  const certsTree = new x509.X509Certificates();

  before(async () => {
    const pems = [
      `-----BEGIN CERTIFICATE-----
MIIBlDCCATmgAwIBAgIUf2jj+cgKVMw5pD1GMocG1YpExEwwCgYIKoZIzj0EAwIw
JjEVMBMGA1UEAxMMUm9vdCBDQSBjZXJ0MQ0wCwYDVQQKEwRUZXN0MB4XDTIyMTIy
NjA2NDIwNloXDTQyMTIyNjA2NDIwNlowJjEVMBMGA1UEAxMMUm9vdCBDQSBjZXJ0
MQ0wCwYDVQQKEwRUZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEO60ORwIK
ZfZ0wxiqf97Mezc28fVFVnuyNCnTNVm2iztE03K3ZrLD0rZuohvJmNvB1DdgZSJS
NHIYp7U8LnKh36NFMEMwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8C
AQEwHQYDVR0OBBYEFLlAZeqsu58hI2DV8kaz4aLR2YHbMAoGCCqGSM49BAMCA0kA
MEYCIQDNC+Qqd5qL0VFzc4Cpk5flsxWtADnKr+bO/QeX7f0VPwIhANUETaqaXkpj
Cuv/UlaFeXwPEDtbvhgY8FIBW8CNRLyA
-----END CERTIFICATE-----`,
      `-----BEGIN CERTIFICATE-----
MIICajCCAhGgAwIBAgIUfw1rwZ/YgkthPxrsy0Tq/epRLmMwCgYIKoZIzj0EAwIw
JjEVMBMGA1UEAxMMUm9vdCBDQSBjZXJ0MQ0wCwYDVQQKEwRUZXN0MB4XDTIyMTIy
NjA2NDIwNloXDTMyMTIyNjA2NDIwNlowLjEdMBsGA1UEAxMUSW50ZXJtZWRpYXRl
IENBIGNlcnQxDTALBgNVBAoTBFRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AATbkHNu+8Co/+TSG0Pufs/HEs5SELP39OCzKovPbUYSA8IHJF95Rh+wfPcOcLMk
b/r5Nb9WigwrJNosmdApaNbfo4IBEzCCAQ8wDgYDVR0PAQH/BAQDAgEGMBIGA1Ud
EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFPu3XMGqhbPRsLmHqguYSBura+VTMB8G
A1UdIwQYMBaAFLlAZeqsu58hI2DV8kaz4aLR2YHbMDQGA1UdJQQtMCsGCCsGAQUF
BwMCBggrBgEFBQcDBAYKKwYBBAGCNwoDDAYJYIZIAYb6aygLMD4GCCsGAQUFBwEB
BDIwMDAuBggrBgEFBQcwAoYiaHR0cHM6Ly9sb2NhbGhvc3Q6ODAwMC9yb290LWNh
LmNlcjAzBgNVHR8ELDAqMCigJqAkhiJodHRwczovL2xvY2FsaG9zdDo4MDAwL3Jv
b3QtY2EuY3JsMAoGCCqGSM49BAMCA0cAMEQCIF/+Ggzw4Pm7OvCrcekUA1/zMk9B
e0L6M67T90dD0E1bAiAOeDfLu0bFCF4YANfOOkOL3howf8ZGsSkes5lYiDsyuQ==
-----END CERTIFICATE-----`,
      `-----BEGIN CERTIFICATE-----
MIICajCCAhGgAwIBAgIUf1UGkdteyPJ3mXOh8Rwdnd1udo8wCgYIKoZIzj0EAwIw
JjEVMBMGA1UEAxMMUm9vdCBDQSBjZXJ0MQ0wCwYDVQQKEwRUZXN0MB4XDTIyMTIy
NjA2NDIwNloXDTMzMTIyNjA2NDIwNlowLjEdMBsGA1UEAxMUSW50ZXJtZWRpYXRl
IENBIGNlcnQxDTALBgNVBAoTBFRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AATbkHNu+8Co/+TSG0Pufs/HEs5SELP39OCzKovPbUYSA8IHJF95Rh+wfPcOcLMk
b/r5Nb9WigwrJNosmdApaNbfo4IBEzCCAQ8wDgYDVR0PAQH/BAQDAgEGMBIGA1Ud
EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFPu3XMGqhbPRsLmHqguYSBura+VTMB8G
A1UdIwQYMBaAFLlAZeqsu58hI2DV8kaz4aLR2YHbMDQGA1UdJQQtMCsGCCsGAQUF
BwMCBggrBgEFBQcDBAYKKwYBBAGCNwoDDAYJYIZIAYb6aygLMD4GCCsGAQUFBwEB
BDIwMDAuBggrBgEFBQcwAoYiaHR0cHM6Ly9sb2NhbGhvc3Q6ODAwMC9yb290LWNh
LmNlcjAzBgNVHR8ELDAqMCigJqAkhiJodHRwczovL2xvY2FsaG9zdDo4MDAwL3Jv
b3QtY2EuY3JsMAoGCCqGSM49BAMCA0cAMEQCIEztc/6I/ZmnCc8SlG/cywtQ5kDV
Bazy1QpYznxEOYCdAiAQh3CocvGnNsZM/oPSRXeuhEaXZDa4N7/tm58OHvY97g==
-----END CERTIFICATE-----`,
      `-----BEGIN CERTIFICATE-----
MIICdTCCAhugAwIBAgIUfxnEkpHrr45lBnTg6xIrjGVf5eEwCgYIKoZIzj0EAwIw
LjEdMBsGA1UEAxMUSW50ZXJtZWRpYXRlIENBIGNlcnQxDTALBgNVBAoTBFRlc3Qw
HhcNMjIxMjI2MDY0MjA2WhcNMzAxMjI2MDY0MjA2WjAwMR8wHQYDVQQDExZJbnRl
cm1lZGlhdGUgQ0EgY2VydCAyMQ0wCwYDVQQKEwRUZXN0MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAELsrIM/ggFlFh8lPYTc++wmAYRgzu9uEnQ6fEYCMKW6xhm8eT
+6VOn778ige80ghDI7jGedwXQpupB9UoSHIcPaOCARMwggEPMA4GA1UdDwEB/wQE
AwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTDQOJ+ILUOWkQeYjEX
rp5eaTPtWjAfBgNVHSMEGDAWgBT7t1zBqoWz0bC5h6oLmEgbq2vlUzA0BgNVHSUE
LTArBggrBgEFBQcDAgYIKwYBBQUHAwQGCisGAQQBgjcKAwwGCWCGSAGG+msoCzA+
BggrBgEFBQcBAQQyMDAwLgYIKwYBBQUHMAKGImh0dHBzOi8vbG9jYWxob3N0Ojgw
MDAvcm9vdC1jYS5jZXIwMwYDVR0fBCwwKjAooCagJIYiaHR0cHM6Ly9sb2NhbGhv
c3Q6ODAwMC9yb290LWNhLmNybDAKBggqhkjOPQQDAgNIADBFAiEA1shsEZVejICl
rMOygvtCNOnCtkBJi+mDPmpa2rjHNpoCIElnpb/gGOt5uHNJyX+i7abIagrg7GAv
/3hTFUKAAIBQ
-----END CERTIFICATE-----`,
      `-----BEGIN CERTIFICATE-----
MIICdDCCAhugAwIBAgIUf4R93WceOdqW3vbqBA/dAX0Nt+IwCgYIKoZIzj0EAwIw
LjEdMBsGA1UEAxMUSW50ZXJtZWRpYXRlIENBIGNlcnQxDTALBgNVBAoTBFRlc3Qw
HhcNMjIxMjI2MDY0MjA2WhcNMzAxMjI2MDY0MjA2WjAwMR8wHQYDVQQDExZJbnRl
cm1lZGlhdGUgQ0EgY2VydCAyMQ0wCwYDVQQKEwRUZXN0MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAELsrIM/ggFlFh8lPYTc++wmAYRgzu9uEnQ6fEYCMKW6xhm8eT
+6VOn778ige80ghDI7jGedwXQpupB9UoSHIcPaOCARMwggEPMA4GA1UdDwEB/wQE
AwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTDQOJ+ILUOWkQeYjEX
rp5eaTPtWjAfBgNVHSMEGDAWgBT7t1zBqoWz0bC5h6oLmEgbq2vlUzA0BgNVHSUE
LTArBggrBgEFBQcDAgYIKwYBBQUHAwQGCisGAQQBgjcKAwwGCWCGSAGG+msoCzA+
BggrBgEFBQcBAQQyMDAwLgYIKwYBBQUHMAKGImh0dHBzOi8vbG9jYWxob3N0Ojgw
MDAvcm9vdC1jYS5jZXIwMwYDVR0fBCwwKjAooCagJIYiaHR0cHM6Ly9sb2NhbGhv
c3Q6ODAwMC9yb290LWNhLmNybDAKBggqhkjOPQQDAgNHADBEAiAE5GMn7gMYzT2k
IOkrKcMuhjWBd5A/MHGjgjIhxWgvxwIgMWvxpF+bFHNYNI3R6g9mEKmxOmOtlA85
NiXJIDi481Q=
-----END CERTIFICATE-----`,
      `-----BEGIN CERTIFICATE-----
MIICdzCCAh2gAwIBAgIUf6GxFUpBX6d5XbJx4tEdzrvVP2EwCgYIKoZIzj0EAwIw
MDEfMB0GA1UEAxMWSW50ZXJtZWRpYXRlIENBIGNlcnQgMjENMAsGA1UEChMEVGVz
dDAeFw0yMjEyMjYwNjQyMDZaFw0yOTEyMjYwNjQyMDZaMDAxHzAdBgNVBAMTFklu
dGVybWVkaWF0ZSBDQSBjZXJ0IDQxDTALBgNVBAoTBFRlc3QwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAASQxMPRZ47F0beWGaJ9Y/oGN2xpwnKnh/Qiv0sU9WAYY3Wo
JzKJUKUNisdwnPGumYzpzioRHWh/HXU6nD9mpRL7o4IBEzCCAQ8wDgYDVR0PAQH/
BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFLsqv0Nk0Y7PevkG
zvuYNg6uB+wAMB8GA1UdIwQYMBaAFMNA4n4gtQ5aRB5iMReunl5pM+1aMDQGA1Ud
JQQtMCsGCCsGAQUFBwMCBggrBgEFBQcDBAYKKwYBBAGCNwoDDAYJYIZIAYb6aygL
MD4GCCsGAQUFBwEBBDIwMDAuBggrBgEFBQcwAoYiaHR0cHM6Ly9sb2NhbGhvc3Q6
ODAwMC9yb290LWNhLmNlcjAzBgNVHR8ELDAqMCigJqAkhiJodHRwczovL2xvY2Fs
aG9zdDo4MDAwL3Jvb3QtY2EuY3JsMAoGCCqGSM49BAMCA0gAMEUCIQDx7IF2M7Sk
bhfeCt1wkwGisDgSAqOZWLiI0+GTTlqvRgIgZIb7vebpC65vIbD6oBG+QphUdirr
CEn5YlJTjpTwKK0=
-----END CERTIFICATE-----`
    ];

    pems.forEach((pem) => certsTree.push(new x509.X509Certificate(pem)));
  });

  it("build chain tree", async () => {
    const chain = new x509.X509CertificateTree();
    chain.certificateStorage.certificates = certsTree;
    const certificateChain: x509.X509Certificate[] = [];
    const certificateChains = new x509.X509ChainBuilderFromTree();
    const items = await chain.buildTree(certsTree[5]);
    const array = certificateChains.build(items, certificateChain);
    assert.strictEqual(array.length, 4);
    array.forEach(item => assert.strictEqual(item.length, 4));
  });

  it("self-signed certificate chain", async () => {
    const chain = new x509.X509CertificateTree();
    chain.certificateStorage.certificates = certsTree;
    const certificateChain: x509.X509Certificate[] = [];
    const certificateChains = new x509.X509ChainBuilderFromTree();
    const items = await chain.buildTree(certsTree[0]);
    const array = certificateChains.build(items, certificateChain);
    assert.strictEqual(array.length, 1);
    array.forEach(item => assert.strictEqual(item.map(o => o.subject).join(","), "CN=Root CA cert, O=Test"));
  });

  it("build certificates chain", async () => {
    const chain = new x509.X509CertificateTree();
    chain.certificateStorage.certificates = certsTree;
    const certificateChain: x509.X509Certificate[] = [];
    const certificateChains = new x509.X509ChainBuilderFromTree();
    const items = await chain.buildTree(certsTree[5]);
    const array = certificateChains.build(items, certificateChain);
    array.forEach(item => assert.strictEqual(item.length, 4));
    array.forEach(item => assert.strictEqual(item.map(o => o.subject).join(","), "CN=Intermediate CA cert 4, O=Test,CN=Intermediate CA cert 2, O=Test,CN=Intermediate CA cert, O=Test,CN=Root CA cert, O=Test"));
  });

  it("Rule for checking certificate chains for cyclicity", async () => {
    const chain = new x509.X509CertificateTree();
    chain.certificateStorage.certificates = certsTree;
    const certificateChain: x509.X509Certificate[] = [];
    const certificateChains = new x509.X509ChainBuilderFromTree();
    const items = await chain.buildTree(certsTree[5]);
    const array = certificateChains.build(items, certificateChain);
    for (const chain of array) {
      const params: ChainRuleValidateParams = {
        node: items,
        cert: certsTree[5],
        chain: chain as x509.X509Certificates,
        options: '',
        checkDate: new Date("2023/08/18"),
      };
      const rule: ChainRule = new CyclicRule();
      RulesRegistry.items = [];
      RulesRegistry.register(rule);
      const result = await Rules.validates(params);
      for (const item of result[0]) {
        assert.strictEqual(item.results[0].status, true);
        assert.strictEqual(item.results[0].details, 'The certificate chain is valid');
        assert.strictEqual(item.status, true);
        assert.strictEqual(item.certificate, chain[0]);
      }
    }
  });

  it("Rule for checking certificate chains for trusted", async () => {
    const chain = new x509.X509CertificateTree();
    chain.certificateStorage.certificates = certsTree;
    const certificateChain: x509.X509Certificate[] = [];
    const certificateChains = new x509.X509ChainBuilderFromTree();
    const items = await chain.buildTree(certsTree[5]);
    const array = certificateChains.build(items, certificateChain);
    for (const chain of array) {
      const params: ChainRuleValidateParams = {
        node: items,
        cert: certsTree[5],
        chain: chain as x509.X509Certificates,
        options: '',
        checkDate: new Date("2023/08/18"),
      };
      const rule: ChainRule = new TrustedRule();
      RulesRegistry.items = [];
      RulesRegistry.register(rule);
      const result = await Rules.validates(params);
      assert.strictEqual(result[0].length, 4);
      for (const item of result[0]) {
        assert.strictEqual(item.results[0].details, 'Parent certificates are not included in trusted list');
      }
    }
  });

  it("Rule for checking certificate chains for valid", async () => {
    const chain = new x509.X509CertificateTree();
    chain.certificateStorage.certificates = certsTree;
    const certificateChain: x509.X509Certificate[] = [];
    const certificateChains = new x509.X509ChainBuilderFromTree();
    const items = await chain.buildTree(certsTree[5]);
    const array = certificateChains.build(items, certificateChain);
    for (const chain of array) {
      const params: ChainRuleValidateParams = {
        node: items,
        cert: certsTree[5],
        chain: chain as x509.X509Certificates,
        options: '',
        checkDate: new Date("2023/08/18"),
      };
      const rule: ChainRule = new ExpiredRule();
      RulesRegistry.items = [];
      RulesRegistry.register(rule);
      const result = await Rules.validates(params);
      assert.strictEqual(result[0].length, 4);
      for (const item of result[0]) {
        assert.strictEqual(item.results[0].details, 'The certificate is valid');
      }
    }
  });

  it("Rule for checking certificate chains for not yet valid", async () => {
    const chain = new x509.X509CertificateTree();
    chain.certificateStorage.certificates = certsTree;
    const certificateChain: x509.X509Certificate[] = [];
    const certificateChains = new x509.X509ChainBuilderFromTree();
    const items = await chain.buildTree(certsTree[5]);
    const array = certificateChains.build(items, certificateChain);
    for (const chain of array) {
      const params: ChainRuleValidateParams = {
        node: items,
        cert: certsTree[5],
        chain: chain as x509.X509Certificates,
        options: '',
        checkDate: new Date("2020/08/18"),
      };
      const rule: ChainRule = new ExpiredRule();
      RulesRegistry.items = [];
      RulesRegistry.register(rule);
      const result = await Rules.validates(params);
      assert.strictEqual(result[0].length, 4);
      for (const item of result[0]) {
        assert.strictEqual(item.results[0].details, 'The certificate is not yet valid');
      }
    }
  });

  it("Rule for checking certificate chains for expired", async () => {
    const chain = new x509.X509CertificateTree();
    chain.certificateStorage.certificates = certsTree;
    const certificateChain: x509.X509Certificate[] = [];
    const certificateChains = new x509.X509ChainBuilderFromTree();
    const items = await chain.buildTree(certsTree[5]);
    const array = certificateChains.build(items, certificateChain);
    for (const chain of array) {
      const params: ChainRuleValidateParams = {
        node: items,
        cert: certsTree[5],
        chain: chain as x509.X509Certificates,
        options: '',
        checkDate: new Date("2043/08/18"),
      };
      const rule: ChainRule = new ExpiredRule();
      RulesRegistry.items = [];
      RulesRegistry.register(rule);
      const result = await Rules.validates(params);
      assert.strictEqual(result[0].length, 4);
      for (const item of result[0]) {
        assert.strictEqual(item.results[0].details, 'The certificate is expired');
      }
    }
  });

  it("Rule for checking certificate chains for mixed states", async () => {
    const chain = new x509.X509CertificateTree();
    chain.certificateStorage.certificates = certsTree;
    const certificateChain: x509.X509Certificate[] = [];
    const certificateChains = new x509.X509ChainBuilderFromTree();
    const items = await chain.buildTree(certsTree[5]);
    const array = certificateChains.build(items, certificateChain);
    for (const chain of array) {
      const params: ChainRuleValidateParams = {
        node: items,
        cert: certsTree[5],
        chain: chain as x509.X509Certificates,
        options: '',
        checkDate: new Date("2031/12/26"),
      };
      const rule: ChainRule = new ExpiredRule();
      RulesRegistry.items = [];
      RulesRegistry.register(rule);
      const result = await Rules.validates(params);
      assert.strictEqual(result[0].length, 4);
      let valid = '';
      for (let i = 0; i < result[0].length; i++) {
        if (i % 4 === 0 || i % 4 === 1) { valid = 'The certificate is expired'; }
        if (i % 4 === 2 || i % 4 === 3) { valid = 'The certificate is valid'; }
        assert.strictEqual(result[0][i].results[0].details, valid);
      }
    }
  });

  it("Certificate chains validation rules", async () => {
    const chain = new x509.X509CertificateTree();
    chain.certificateStorage.certificates = certsTree;
    const certificateChain: x509.X509Certificate[] = [];
    const certificateChains = new x509.X509ChainBuilderFromTree();
    const items = await chain.buildTree(certsTree[5]);
    const array = certificateChains.build(items, certificateChain);
    for (const chain of array) {
      const params: ChainRuleValidateParams = {
        node: items,
        cert: certsTree[5],
        chain: chain as x509.X509Certificates,
        options: '',
        checkDate: new Date("2031/12/26"),
      };
      RulesRegistry.items = [];
      const testData = [new CyclicRule, new TrustedRule, new ExpiredRule];
      for (let i = 0; i < testData.length; i++) {
        RulesRegistry.register(testData[i]);
      }
      const result = await Rules.validates(params);
      for (let i = 0; i < result.length; i++) {
        if (i === 0) {
          assert.strictEqual(result[i].length, 1);
          assert.strictEqual(result[i][0].results[0].details, 'The certificate chain is valid');
          assert.strictEqual(result[i][0].status, true);
          assert.strictEqual(result[i][0].certificate, chain[0]);
        } else if (i === 1) {
          assert.strictEqual(result[i].length, 4);
          assert.strictEqual(result[i][0].results[0].details, 'Parent certificates are not included in trusted list');
        } else {
          assert.strictEqual(result[i].length, 4);
          let valid = '';
          for (let j = 0; j < result[0].length; j++) {
            if (j % 4 === 0 || j % 4 === 1) { valid = 'The certificate is expired'; }
            if (j % 4 === 2 || j % 4 === 3) { valid = 'The certificate is valid'; }
            assert.strictEqual(result[i][j].results[0].details, valid);
          }
        }
      }
      assert.strictEqual(result.length, 3);
    }
  });
});