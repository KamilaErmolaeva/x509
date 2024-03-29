import * as assert from "assert";
import * as x509 from "../src";
import { AuthorityInformationAccessExtension } from "../src/extensions";
import { OCSPResponse } from "../src/ocsp";

context("OCSP", async () => {

  const pemLeaf = `-----BEGIN CERTIFICATE-----
MIIGGDCCBZ2gAwIBAgITMwAABF8rDWWdcXI+fQAAAAAEXzAKBggqhkjOPQQDAzBd
MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS4w
LAYDVQQDEyVNaWNyb3NvZnQgQXp1cmUgRUNDIFRMUyBJc3N1aW5nIENBIDA4MB4X
DTI0MDEzMDAyMTUyNFoXDTI1MDEyNDAyMTUyNFowajELMAkGA1UEBhMCVVMxCzAJ
BgNVBAgTAldBMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
Q29ycG9yYXRpb24xHDAaBgNVBAMTE2xlYXJuLm1pY3Jvc29mdC5jb20wWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAQD5AJSeo8MVxxZXh4eCMmV3Yfbrc19Fd0REslo
cnHRDmrq6IFvYRwC0pqR/xjELJiAP+WF1Obdg7xAnhd7GmESo4IELTCCBCkwggF9
BgorBgEEAdZ5AgQCBIIBbQSCAWkBZwB1AM8RVu7VLnyv84db2Wkum+kacWdKsBfs
rAHSW3fOzDsIAAABjVgvj+0AAAQDAEYwRAIgY2PzrG1ChzV4szR6fE1xFPHP6vLS
aShFsYbJkSkjlLoCIFb6oNcpWWuzK20MJvoJwNZYUl7n/bsX0AzIpoEhMaKYAHYA
fVkeEuF4KnscYWd8Xv340IdcFKBOlZ65Ay/ZDowuebgAAAGNWC+Q1AAABAMARzBF
AiEArps9RATMRAKj4WpKwNb+mPVAVPRv5Ir8iR1GnftpNioCIGNi+EyPvdc6iB9R
/lnV1wTpgKeHRJcdisZepdXbVuVLAHYAVYHUwhaQNgFK6gubVzxT8MDkOHhwJQgX
L6OqHQcT0wwAAAGNWC+QwgAABAMARzBFAiEA+W72vqC7fR2Ko0R7TGh7ue0I/Si/
mG69h128xewl6QICICPU53lockSfHEn++TospCqyM/EcRlx87UuvrX17t9zVMCcG
CSsGAQQBgjcVCgQaMBgwCgYIKwYBBQUHAwIwCgYIKwYBBQUHAwEwPAYJKwYBBAGC
NxUHBC8wLQYlKwYBBAGCNxUIh73XG4Hn60aCgZ0ujtAMh/DaHV2ChOVpgvOnPgIB
ZAIBJjCBtAYIKwYBBQUHAQEEgacwgaQwcwYIKwYBBQUHMAKGZ2h0dHA6Ly93d3cu
bWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwQXp1cmUlMjBF
Q0MlMjBUTFMlMjBJc3N1aW5nJTIwQ0ElMjAwOCUyMC0lMjB4c2lnbi5jcnQwLQYI
KwYBBQUHMAGGIWh0dHA6Ly9vbmVvY3NwLm1pY3Jvc29mdC5jb20vb2NzcDAdBgNV
HQ4EFgQURohnyebpes3pcn7gdTIKBunVj24wDgYDVR0PAQH/BAQDAgeAMDcGA1Ud
EQQwMC6CF3d3dy5sZWFybi5taWNyb3NvZnQuY29tghNsZWFybi5taWNyb3NvZnQu
Y29tMAwGA1UdEwEB/wQCMAAwagYDVR0fBGMwYTBfoF2gW4ZZaHR0cDovL3d3dy5t
aWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwQXp1cmUlMjBFQ0Ml
MjBUTFMlMjBJc3N1aW5nJTIwQ0ElMjAwOC5jcmwwZgYDVR0gBF8wXTBRBgwrBgEE
AYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
L3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMAgGBmeBDAECAjAfBgNVHSMEGDAW
gBStVB0DVHHGL17WWxhYzm4kxdaiCjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYB
BQUHAwEwCgYIKoZIzj0EAwMDaQAwZgIxAPcv4LizT5USJJ9KeCV4z1DGq4R56VE7
Dj1HYgkk45BSrXAQZaMy9wOBl414Gyev2gIxAIGGiBW4YvWldD5BkIatfX8DkP1L
mtIXPcp+B0BYlDTzyaMOp9xtno+ZJgYXvSRrYg==
-----END CERTIFICATE-----`;

  const pemCA = `-----BEGIN CERTIFICATE-----
MIIDXDCCAuOgAwIBAgIQDvLl2DaBUgJV6Sxgj7wv9DAKBggqhkjOPQQDAzBhMQsw
CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
ZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBHMzAe
Fw0yMzA2MDgwMDAwMDBaFw0yNjA4MjUyMzU5NTlaMF0xCzAJBgNVBAYTAlVTMR4w
HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLjAsBgNVBAMTJU1pY3Jvc29m
dCBBenVyZSBFQ0MgVExTIElzc3VpbmcgQ0EgMDgwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAATlQzoKIJQIe8bd4sX2x9XBtFvoh5m7Neph3MYORvv/rg2Ew7Cfb00eZ+zS
njUosyOUCspenehe0PyKtmq6pPshLu5Ww/hLEoQT3drwxZ5PaYHmGEGoy2aPBeXa
23k5ruijggFiMIIBXjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBStVB0D
VHHGL17WWxhYzm4kxdaiCjAfBgNVHSMEGDAWgBSz20ik+aHF2K42QcwRY2liKbxL
xjAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MHYGCCsGAQUFBwEBBGowaDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNl
cnQuY29tMEAGCCsGAQUFBzAChjRodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20v
RGlnaUNlcnRHbG9iYWxSb290RzMuY3J0MEIGA1UdHwQ7MDkwN6A1oDOGMWh0dHA6
Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RHMy5jcmwwHQYD
VR0gBBYwFDAIBgZngQwBAgEwCAYGZ4EMAQICMAoGCCqGSM49BAMDA2cAMGQCMD+q
5Uq1fSGZSKRhrnWKKXlp4DvfZCEU/MF3rbdwAaXI/KVM65YRO9HvRbfDpV3x1wIw
CHvqqpg/8YJPDn8NJIS/Rg+lYraOseXeuNYzkjeY6RLxIDB+nLVDs9QJ3/co89Cd
-----END CERTIFICATE-----`;

const pem1 = `-----BEGIN CERTIFICATE-----
MIIOXTCCDUWgAwIBAgIRAMOJ2F6UsktpCewqqWxlilowDQYJKoZIhvcNAQELBQAw
RjELMAkGA1UEBhMCVVMxIjAgBgNVBAoTGUdvb2dsZSBUcnVzdCBTZXJ2aWNlcyBM
TEMxEzARBgNVBAMTCkdUUyBDQSAxQzMwHhcNMjQwMjA1MDgwMzU2WhcNMjQwNDI5
MDgwMzU1WjAXMRUwEwYDVQQDDAwqLmdvb2dsZS5jb20wWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAASZiguMxLMN3xsvxAltnX7VTQ9V/Wm+cRELSQa38LAc0rgNMUeV
y0zb9DH1R9DNUvqZS9AyEa/tXXb9oJtQ8Zato4IMPjCCDDowDgYDVR0PAQH/BAQD
AgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYE
FAzKvLnKXHitZnAp3RaAm6N4frLkMB8GA1UdIwQYMBaAFIp0f6+Fze6VzT2c0OJG
FPNxNR0nMGoGCCsGAQUFBwEBBF4wXDAnBggrBgEFBQcwAYYbaHR0cDovL29jc3Au
cGtpLmdvb2cvZ3RzMWMzMDEGCCsGAQUFBzAChiVodHRwOi8vcGtpLmdvb2cvcmVw
by9jZXJ0cy9ndHMxYzMuZGVyMIIJ7wYDVR0RBIIJ5jCCCeKCDCouZ29vZ2xlLmNv
bYIWKi5hcHBlbmdpbmUuZ29vZ2xlLmNvbYIJKi5iZG4uZGV2ghUqLm9yaWdpbi10
ZXN0LmJkbi5kZXaCEiouY2xvdWQuZ29vZ2xlLmNvbYIYKi5jcm93ZHNvdXJjZS5n
b29nbGUuY29tghgqLmRhdGFjb21wdXRlLmdvb2dsZS5jb22CCyouZ29vZ2xlLmNh
ggsqLmdvb2dsZS5jbIIOKi5nb29nbGUuY28uaW6CDiouZ29vZ2xlLmNvLmpwgg4q
Lmdvb2dsZS5jby51a4IPKi5nb29nbGUuY29tLmFygg8qLmdvb2dsZS5jb20uYXWC
DyouZ29vZ2xlLmNvbS5icoIPKi5nb29nbGUuY29tLmNvgg8qLmdvb2dsZS5jb20u
bXiCDyouZ29vZ2xlLmNvbS50coIPKi5nb29nbGUuY29tLnZuggsqLmdvb2dsZS5k
ZYILKi5nb29nbGUuZXOCCyouZ29vZ2xlLmZyggsqLmdvb2dsZS5odYILKi5nb29n
bGUuaXSCCyouZ29vZ2xlLm5sggsqLmdvb2dsZS5wbIILKi5nb29nbGUucHSCDyou
Z29vZ2xlYXBpcy5jboIRKi5nb29nbGV2aWRlby5jb22CDCouZ3N0YXRpYy5jboIQ
Ki5nc3RhdGljLWNuLmNvbYIPZ29vZ2xlY25hcHBzLmNughEqLmdvb2dsZWNuYXBw
cy5jboIRZ29vZ2xlYXBwcy1jbi5jb22CEyouZ29vZ2xlYXBwcy1jbi5jb22CDGdr
ZWNuYXBwcy5jboIOKi5na2VjbmFwcHMuY26CEmdvb2dsZWRvd25sb2Fkcy5jboIU
Ki5nb29nbGVkb3dubG9hZHMuY26CEHJlY2FwdGNoYS5uZXQuY26CEioucmVjYXB0
Y2hhLm5ldC5jboIQcmVjYXB0Y2hhLWNuLm5ldIISKi5yZWNhcHRjaGEtY24ubmV0
ggt3aWRldmluZS5jboINKi53aWRldmluZS5jboIRYW1wcHJvamVjdC5vcmcuY26C
EyouYW1wcHJvamVjdC5vcmcuY26CEWFtcHByb2plY3QubmV0LmNughMqLmFtcHBy
b2plY3QubmV0LmNughdnb29nbGUtYW5hbHl0aWNzLWNuLmNvbYIZKi5nb29nbGUt
YW5hbHl0aWNzLWNuLmNvbYIXZ29vZ2xlYWRzZXJ2aWNlcy1jbi5jb22CGSouZ29v
Z2xlYWRzZXJ2aWNlcy1jbi5jb22CEWdvb2dsZXZhZHMtY24uY29tghMqLmdvb2ds
ZXZhZHMtY24uY29tghFnb29nbGVhcGlzLWNuLmNvbYITKi5nb29nbGVhcGlzLWNu
LmNvbYIVZ29vZ2xlb3B0aW1pemUtY24uY29tghcqLmdvb2dsZW9wdGltaXplLWNu
LmNvbYISZG91YmxlY2xpY2stY24ubmV0ghQqLmRvdWJsZWNsaWNrLWNuLm5ldIIY
Ki5mbHMuZG91YmxlY2xpY2stY24ubmV0ghYqLmcuZG91YmxlY2xpY2stY24ubmV0
gg5kb3VibGVjbGljay5jboIQKi5kb3VibGVjbGljay5jboIUKi5mbHMuZG91Ymxl
Y2xpY2suY26CEiouZy5kb3VibGVjbGljay5jboIRZGFydHNlYXJjaC1jbi5uZXSC
EyouZGFydHNlYXJjaC1jbi5uZXSCHWdvb2dsZXRyYXZlbGFkc2VydmljZXMtY24u
Y29tgh8qLmdvb2dsZXRyYXZlbGFkc2VydmljZXMtY24uY29tghhnb29nbGV0YWdz
ZXJ2aWNlcy1jbi5jb22CGiouZ29vZ2xldGFnc2VydmljZXMtY24uY29tghdnb29n
bGV0YWdtYW5hZ2VyLWNuLmNvbYIZKi5nb29nbGV0YWdtYW5hZ2VyLWNuLmNvbYIY
Z29vZ2xlc3luZGljYXRpb24tY24uY29tghoqLmdvb2dsZXN5bmRpY2F0aW9uLWNu
LmNvbYIkKi5zYWZlZnJhbWUuZ29vZ2xlc3luZGljYXRpb24tY24uY29tghZhcHAt
bWVhc3VyZW1lbnQtY24uY29tghgqLmFwcC1tZWFzdXJlbWVudC1jbi5jb22CC2d2
dDEtY24uY29tgg0qLmd2dDEtY24uY29tggtndnQyLWNuLmNvbYINKi5ndnQyLWNu
LmNvbYILMm1kbi1jbi5uZXSCDSouMm1kbi1jbi5uZXSCFGdvb2dsZWZsaWdodHMt
Y24ubmV0ghYqLmdvb2dsZWZsaWdodHMtY24ubmV0ggxhZG1vYi1jbi5jb22CDiou
YWRtb2ItY24uY29tghRnb29nbGVzYW5kYm94LWNuLmNvbYIWKi5nb29nbGVzYW5k
Ym94LWNuLmNvbYIeKi5zYWZlbnVwLmdvb2dsZXNhbmRib3gtY24uY29tgg0qLmdz
dGF0aWMuY29tghQqLm1ldHJpYy5nc3RhdGljLmNvbYIKKi5ndnQxLmNvbYIRKi5n
Y3BjZG4uZ3Z0MS5jb22CCiouZ3Z0Mi5jb22CDiouZ2NwLmd2dDIuY29tghAqLnVy
bC5nb29nbGUuY29tghYqLnlvdXR1YmUtbm9jb29raWUuY29tggsqLnl0aW1nLmNv
bYILYW5kcm9pZC5jb22CDSouYW5kcm9pZC5jb22CEyouZmxhc2guYW5kcm9pZC5j
b22CBGcuY26CBiouZy5jboIEZy5jb4IGKi5nLmNvggZnb28uZ2yCCnd3dy5nb28u
Z2yCFGdvb2dsZS1hbmFseXRpY3MuY29tghYqLmdvb2dsZS1hbmFseXRpY3MuY29t
ggpnb29nbGUuY29tghJnb29nbGVjb21tZXJjZS5jb22CFCouZ29vZ2xlY29tbWVy
Y2UuY29tgghnZ3BodC5jboIKKi5nZ3BodC5jboIKdXJjaGluLmNvbYIMKi51cmNo
aW4uY29tggh5b3V0dS5iZYILeW91dHViZS5jb22CDSoueW91dHViZS5jb22CFHlv
dXR1YmVlZHVjYXRpb24uY29tghYqLnlvdXR1YmVlZHVjYXRpb24uY29tgg95b3V0
dWJla2lkcy5jb22CESoueW91dHViZWtpZHMuY29tggV5dC5iZYIHKi55dC5iZYIa
YW5kcm9pZC5jbGllbnRzLmdvb2dsZS5jb22CG2RldmVsb3Blci5hbmRyb2lkLmdv
b2dsZS5jboIcZGV2ZWxvcGVycy5hbmRyb2lkLmdvb2dsZS5jboIYc291cmNlLmFu
ZHJvaWQuZ29vZ2xlLmNughpkZXZlbG9wZXIuY2hyb21lLmdvb2dsZS5jboIYd2Vi
LmRldmVsb3BlcnMuZ29vZ2xlLmNuMCEGA1UdIAQaMBgwCAYGZ4EMAQIBMAwGCisG
AQQB1nkCBQMwPAYDVR0fBDUwMzAxoC+gLYYraHR0cDovL2NybHMucGtpLmdvb2cv
Z3RzMWMzL3pkQVR0MEV4X0ZrLmNybDCCAQMGCisGAQQB1nkCBAIEgfQEgfEA7wB1
AO7N0GTV2xrOxVy3nbTNE6Iyh0Z8vOzew1FIWUZxH7WbAAABjXiClrQAAAQDAEYw
RAIgbCvi5oby5WHPrMp05P9NYN75+j2uDeqoA1Zd3PCz6cMCIGPTiFNzvGbBy9dk
hJBa//NOZl7bwmW6VRBNuXIc6wP0AHYASLDja9qmRzQP5WoC+p0w6xxSActW3SyB
2bu/qznYhHMAAAGNeIKW2wAABAMARzBFAiEAhCIvEdV0qA2FTVcQhgDiRe3Q2umT
QilOQ6xaDQm1izoCIG1kMPQ10dfflJQEtxnMxh1ef0WC4H2SwHO2hFYwwHhjMA0G
CSqGSIb3DQEBCwUAA4IBAQCEZmylC50iRypJpmhLXBGNFJvR1zbU7kI60l/qJYJX
5s/iOkY/eHI7Jvxia2/v5722MVSSTPONcIS4EgWKmcqOnsE4oNUshBdvSUQS523M
YcEMgxo4iftcddvYu6XjutSLKbQQJMey5NkRnsicy4j1OVf48BWMOtf/wPuc7U8R
m92bhe8BOAjGbIhZd4tPMvk67DZMaui5NoPxBuF1257bQDg493V2hIPbkZKlJojn
7okiu/EJnBf3QNzob5FvjbGZQ/03AyQm9SYOdzYgkZLsulLDNCvqZfJwmzd94M7o
j0uf81mlzh+aaq8tf8o7PD8FIu743rQ7oHbQoV1sfMYi
-----END CERTIFICATE-----`;

const pem2 = `-----BEGIN CERTIFICATE-----
MIIFljCCA36gAwIBAgINAgO8U1lrNMcY9QFQZjANBgkqhkiG9w0BAQsFADBHMQsw
CQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEU
MBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMjAwODEzMDAwMDQyWhcNMjcwOTMwMDAw
MDQyWjBGMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZp
Y2VzIExMQzETMBEGA1UEAxMKR1RTIENBIDFDMzCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAPWI3+dijB43+DdCkH9sh9D7ZYIl/ejLa6T/belaI+KZ9hzp
kgOZE3wJCor6QtZeViSqejOEH9Hpabu5dOxXTGZok3c3VVP+ORBNtzS7XyV3NzsX
lOo85Z3VvMO0Q+sup0fvsEQRY9i0QYXdQTBIkxu/t/bgRQIh4JZCF8/ZK2VWNAcm
BA2o/X3KLu/qSHw3TT8An4Pf73WELnlXXPxXbhqW//yMmqaZviXZf5YsBvcRKgKA
gOtjGDxQSYflispfGStZloEAoPtR28p3CwvJlk/vcEnHXG0g/Zm0tOLKLnf9LdwL
tmsTDIwZKxeWmLnwi/agJ7u2441Rj72ux5uxiZ0CAwEAAaOCAYAwggF8MA4GA1Ud
DwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwEgYDVR0T
AQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUinR/r4XN7pXNPZzQ4kYU83E1HScwHwYD
VR0jBBgwFoAU5K8rJnEaK0gnhS9SZizv8IkTcT4waAYIKwYBBQUHAQEEXDBaMCYG
CCsGAQUFBzABhhpodHRwOi8vb2NzcC5wa2kuZ29vZy9ndHNyMTAwBggrBgEFBQcw
AoYkaHR0cDovL3BraS5nb29nL3JlcG8vY2VydHMvZ3RzcjEuZGVyMDQGA1UdHwQt
MCswKaAnoCWGI2h0dHA6Ly9jcmwucGtpLmdvb2cvZ3RzcjEvZ3RzcjEuY3JsMFcG
A1UdIARQME4wOAYKKwYBBAHWeQIFAzAqMCgGCCsGAQUFBwIBFhxodHRwczovL3Br
aS5nb29nL3JlcG9zaXRvcnkvMAgGBmeBDAECATAIBgZngQwBAgIwDQYJKoZIhvcN
AQELBQADggIBAIl9rCBcDDy+mqhXlRu0rvqrpXJxtDaV/d9AEQNMwkYUuxQkq/BQ
cSLbrcRuf8/xam/IgxvYzolfh2yHuKkMo5uhYpSTld9brmYZCwKWnvy15xBpPnrL
RklfRuFBsdeYTWU0AIAaP0+fbH9JAIFTQaSSIYKCGvGjRFsqUBITTcFTNvNCCK9U
+o53UxtkOCcXCb1YyRt8OS1b887U7ZfbFAO/CVMkH8IMBHmYJvJh8VNS/UKMG2Yr
PxWhu//2m+OBmgEGcYk1KCTd4b3rGS3hSMs9WYNRtHTGnXzGsYZbr8w0xNPM1IER
lQCh9BIiAfq0g3GvjLeMcySsN1PCAJA/Ef5c7TaUEDu9Ka7ixzpiO2xj2YC/WXGs
Yye5TBeg2vZzFb8q3o/zpWwygTMD0IZRcZk0upONXbVRWPeyk+gB9lm+cZv9TSjO
z23HFtz30dZGm6fKa+l3D/2gthsjgx0QGtkJAITgRNOidSOzNIb2ILCkXhAd4FJG
AJ2xDx8hcFH1mt0G/FX0Kw4zd8NLQsLxdxP8c4CU6x+7Nz/OAipmsHMdMqUybDKw
juDEI/9bfU1lcKwrmz3O2+BtjjKAvpafkmO8l7tdufThcV4q5O8DIrGKZTqPwJNl
1IXNDw9bg1kWRxYtnCQ6yICmJhSFm/Y3m6xv+cXDBlHz4n/FsRC6UfTd
-----END CERTIFICATE-----`;

// const ocspURL = "http://ocsp.digicert.com/";
// const ocspURL = "http://oneocsp.microsoft.com/ocsp"

  it("generating an OCSP request", async () => {
    const certificate = new x509.X509Certificate(pemLeaf);
    const issuer = new x509.X509Certificate(pemCA);


    // find extension with type  = "1.3.6.1.5.5.7.1.1"
    const authInfoAccess = certificate.extensions.find(obj => obj.type === "1.3.6.1.5.5.7.1.1") as AuthorityInformationAccessExtension;
    if(!authInfoAccess) throw new Error("No Authority Information Access extension found");


    // find OCSP URL and CA Issuers URL

    const ocspURL = authInfoAccess.getOcsp()[0];
    const caIssuers = authInfoAccess.getCaIssuers()[0];


    if(!ocspURL) throw new Error("No OCSP URL found in Authority Information Access extension");

    const request = await x509.ocsp.OCSPRequestGenerator.create({
      certificate,
      issuer,
    });
    assert.ok(request)

    const postRequest = request.rawData;

    // Send get request to OCSP server with the generated OCSP request
    const response = await fetch(ocspURL, {
      method: "POST",
      headers: {
        "Content-Type": "application/ocsp-request",
      },
      body: postRequest,
    });

    assert(response.ok, "OCSP request failed")

    const data = await response.arrayBuffer();
    console.log(data, "hex"); // Logs the ArrayBuffer as a Uint8Array for readability

    // Parse the OCSP response
    const ocspResponse = new OCSPResponse(data);
    console.log(ocspResponse.toString())
    assert.equal(ocspResponse.status, 0, "OCSP response is malformed")
  });
});