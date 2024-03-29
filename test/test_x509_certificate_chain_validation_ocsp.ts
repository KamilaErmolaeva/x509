import { assert } from "console";
import * as x509 from "../src";

const pemsGoogle = [
`-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`,
`-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`,
`-----BEGIN CERTIFICATE-----
MIIFVzCCAz+gAwIBAgINAgPlk28xsBNJiGuiFzANBgkqhkiG9w0BAQwFADBHMQsw
CQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEU
MBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIyMDAw
MDAwWjBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZp
Y2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjEwggIiMA0GCSqGSIb3DQEBAQUA
A4ICDwAwggIKAoICAQC2EQKLHuOhd5s73L+UPreVp0A8of2C+X0yBoJx9vaMf/vo
27xqLpeXo4xL+Sv2sfnOhB2x+cWX3u+58qPpvBKJXqeqUqv4IyfLpLGcY9vXmX7w
Cl7raKb0xlpHDU0QM+NOsROjyBhsS+z8CZDfnWQpJSMHobTSPS5g4M/SCYe7zUjw
TcLCeoiKu7rPWRnWr4+wB7CeMfGCwcDfLqZtbBkOtdh+JhpFAz2weaSUKK0Pfybl
qAj+lug8aJRT7oM6iCsVlgmy4HqMLnXWnOunVmSPlk9orj2XwoSPwLxAwAtcvfaH
szVsrBhQf4TgTM2S0yDpM7xSma8ytSmzJSq0SPly4cpk9+aCEI3oncKKiPo4Zor8
Y/kB+Xj9e1x3+naH+uzfsQ55lVe0vSbv1gHR6xYKu44LtcXFilWr06zqkUspzBmk
MiVOKvFlRNACzqrOSbTqn3yDsEB750Orp2yjj32JgfpMpf/VjsPOS+C12LOORc92
wO1AK/1TD7Cn1TsNsYqiA94xrcx36m97PtbfkSIS5r762DL8EGMUUXLeXdYWk70p
aDPvOmbsB4om3xPXV2V4J95eSRQAogB/mqghtqmxlbCluQ0WEdrHbEg8QOB+DVrN
VjzRlwW5y0vtOUucxD/SVRNuJLDWcfr0wbrM7Rv1/oFB2ACYPTrIrnqYNxgFlQID
AQABo0IwQDAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
FgQU5K8rJnEaK0gnhS9SZizv8IkTcT4wDQYJKoZIhvcNAQEMBQADggIBAJ+qQibb
C5u+/x6Wki4+omVKapi6Ist9wTrYggoGxval3sBOh2Z5ofmmWJyq+bXmYOfg6LEe
QkEzCzc9zolwFcq1JKjPa7XSQCGYzyI0zzvFIoTgxQ6KfF2I5DUkzps+GlQebtuy
h6f88/qBVRRiClmpIgUxPoLW7ttXNLwzldMXG+gnoot7TiYaelpkttGsN/H9oPM4
7HLwEXWdyzRSjeZ2axfG34arJ45JK3VmgRAhpuo+9K4l/3wV3s6MJT/KYnAK9y8J
ZgfIPxz88NtFMN9iiMG1D53Dn0reWVlHxYciNuaCp+0KueIHoI17eko8cdLiA6Ef
MgfdG+RCzgwARWGAtQsgWSl4vflVy2PFPEz0tv/bal8xa5meLMFrUKTX5hgUvYU/
Z6tGn6D/Qqc6f1zLXbBwHSs09dR2CQzreExZBfMzQsNhFRAbd03OIozUhfJFfbdT
6u9AWpQKXCBfTkBdYiJ23//OYb2MI3jSNwLgjt7RETeJ9r/tSQdirpLsQBqvFAnZ
0E6yove+7u7Y/9waLd64NnHi/Hm3lCXRSHNboTXns5lndcEZOitHTtNCjv0xyBZm
2tIMPNuzjsmhDYAPexZ3FL//2wmUspO8IFgV6dtxQ/PeEMMA3KgqlbbC1j+Qa3bb
bP6MvPJwNQzcmRk13NfIRmPVNnGuV/u3gm3c
-----END CERTIFICATE-----`
];

const pemMicrosoft = [
`-----BEGIN CERTIFICATE-----
MIII5TCCBs2gAwIBAgITMwAD4s0QZq2NuBwGCAAAAAPizTANBgkqhkiG9w0BAQwF
ADBdMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
MS4wLAYDVQQDEyVNaWNyb3NvZnQgQXp1cmUgUlNBIFRMUyBJc3N1aW5nIENBIDA3
MB4XDTIzMDkxNDE3MjQyMFoXDTI0MDkwODE3MjQyMFowaDELMAkGA1UEBhMCVVMx
CzAJBgNVBAgTAldBMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
ZnQgQ29ycG9yYXRpb24xGjAYBgNVBAMTEXd3dy5taWNyb3NvZnQuY29tMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsmbP4PGEgfIltEV/Wt6NFwC3OkbR
mtLc/+W9EsJUZNyQZLC5TlLOOy0ux67HPMoiSZrQRJLn99IQJbRXTTZbRR7jz4I9
e8qYO5VehFS0RHkT6M3XYeDTDQfQOAPO7jbZgMKP9XgGqZXsbqoBKyFRPrszVzZW
Zc+dGlZTQnMYkAhltEGgEL8+fN25Gquavt6WSY2vc9Li2Yj9Eoo4+Eo4zJMCKVPE
4bsyC40BBaJEyU5pTdaVMI8K0pyKkLvt2kklryXaamjU9K/zee1joPYGRqVr9fl3
+hJ1ia0VzdnFq3tP+wXFlEr+m8MtpQTwha1Elx1hnuRmFG/YPa9qj+RlNQIDAQAB
o4IEkTCCBI0wggF+BgorBgEEAdZ5AgQCBIIBbgSCAWoBaAB3AHb/iD8KtvuVUcJh
zPWHujS0pM27KdxoQgqf5mdMWjp0AAABipTCG8UAAAQDAEgwRgIhAK9VBkhYoGD8
smdZpGblkGIxh+s76J9DIu2vylLOSX5DAiEAnW9VG6vFtyf+iv+LTiGE0ISGr0hh
itmTJxsgsbV2MQAAdQDatr9rP7W2Ip+bwrtca+hwkXFsu1GEhTS9pD0wSNf7qwAA
AYqUwhw0AAAEAwBGMEQCIGchMFlY/hrw6qyerVfS+IgchU160ugObUp6bbXLcU5x
AiBNOYgiepuAhstFR0OjvTwG0t2oRk8qr+S6/m6vFVAjTgB2AO7N0GTV2xrOxVy3
nbTNE6Iyh0Z8vOzew1FIWUZxH7WbAAABipTCG+0AAAQDAEcwRQIgdPH1Un+uZYyz
/miP1BfUdhmr7FxUSF64j76xNfBr+1ECIQCzUfOkMZuP6HwcBvqUKVnpgGrdGqRl
FWInDI0GIWts+DAnBgkrBgEEAYI3FQoEGjAYMAoGCCsGAQUFBwMCMAoGCCsGAQUF
BwMBMDwGCSsGAQQBgjcVBwQvMC0GJSsGAQQBgjcVCIe91xuB5+tGgoGdLo7QDIfw
2h1dgoTlaYLzpz4CAWQCASYwgbQGCCsGAQUFBwEBBIGnMIGkMHMGCCsGAQUFBzAC
hmdodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29m
dCUyMEF6dXJlJTIwUlNBJTIwVExTJTIwSXNzdWluZyUyMENBJTIwMDclMjAtJTIw
eHNpZ24uY3J0MC0GCCsGAQUFBzABhiFodHRwOi8vb25lb2NzcC5taWNyb3NvZnQu
Y29tL29jc3AwHQYDVR0OBBYEFJRG0f2FZsvVCZPogua5ie3N5ocKMA4GA1UdDwEB
/wQEAwIFoDCBmQYDVR0RBIGRMIGOghN3d3dxYS5taWNyb3NvZnQuY29tghF3d3cu
bWljcm9zb2Z0LmNvbYIYc3RhdGljdmlldy5taWNyb3NvZnQuY29tghFpLnMtbWlj
cm9zb2Z0LmNvbYINbWljcm9zb2Z0LmNvbYIRYy5zLW1pY3Jvc29mdC5jb22CFXBy
aXZhY3kubWljcm9zb2Z0LmNvbTAMBgNVHRMBAf8EAjAAMGoGA1UdHwRjMGEwX6Bd
oFuGWWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29m
dCUyMEF6dXJlJTIwUlNBJTIwVExTJTIwSXNzdWluZyUyMENBJTIwMDcuY3JsMGYG
A1UdIARfMF0wUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93
d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTAIBgZn
gQwBAgIwHwYDVR0jBBgwFoAUzhUWO+oCo6Zr2tkr/eWMUr56UKgwHQYDVR0lBBYw
FAYIKwYBBQUHAwIGCCsGAQUFBwMBMA0GCSqGSIb3DQEBDAUAA4ICAQBuwQV+NfkB
BeNDMcuY1XwsnYhREpo03+hghAjMLwgY7HhwRD46jnTFdD+l9JUv4uXU5vy/UreZ
JbTia0mD76MWwrr70ntDum3nPRLyMDDtr3/n/ZnopCFMrk9WPiITOvcarpNznvaa
kbDWZccj4s6yHafKsruq2wDF5f/LtIRUt3D8pFLZ1nTmbLyiKcV7BKlaGUJyw83B
yCBj2ED0ynKqgssXfO8vdTDzBjMsiY1LtcW0AzlqA20o+7XUxCYmwVyx+3/TKSHs
elRE4hxEZ5lDHwnm2XLBls/BGA/bjIIMRwj+FqKax2jgNA0vBeeLeOt8d75LyupP
147snQDbauEeHRbrJKmDnpdE1JVsVWnYoEj5O39wQb4uBJ1e7SxDdkieydLQyNcJ
qJL/DDEtqlXn7BVunNNb6cPYH+d/KZYdF/Xgp9M0VepIvm8wgnnTNgW66RZTPwT2
7fbI+rnR8lrHSJcFmDPPC7j4IM0RNo2bmEGI4EX9GR7XZ5fuylS1NEIlrap9HIPq
TOR+MsPH4AeH9UyiYvOmxUNZIRTcQwxfWOEEZmvLpzVvROqIy7yxX5f3KGW4Cf45
Unyb2Oj6CDA9YFEcjRuaZBDtSKJ6AYOWFJO7CIHsjAZ0rBqfyfNdBd5DG4+ZJkD8
50WeBZCdbW0GmufXnB4Oa1oIOywDyOG6eQ==
-----END CERTIFICATE-----`,
`-----BEGIN CERTIFICATE-----
MIIFrDCCBJSgAwIBAgIQCkOpUJsBNS+JlXnscgi6UDANBgkqhkiG9w0BAQwFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH
MjAeFw0yMzA2MDgwMDAwMDBaFw0yNjA4MjUyMzU5NTlaMF0xCzAJBgNVBAYTAlVT
MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLjAsBgNVBAMTJU1pY3Jv
c29mdCBBenVyZSBSU0EgVExTIElzc3VpbmcgQ0EgMDcwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQC1ZF7KYus5OO3GWqJoR4xznLDNCjocogqeCIVdi4eE
BmF3zIYeuXXNoJAUF+mn86NBt3yMM0559JZDkiSDi9MpA2By4yqQlTHzfbOrvs7I
4LWsOYTEClVFQgzXqa2ps2g855HPQW1hZXVh/yfmbtrCNVa//G7FPDqSdrAQ+M8w
0364kyZApds/RPcqGORjZNokrNzYcGub27vqE6BGP6XeQO5YDFobi9BvvTOO+ZA9
HGIU7FbdLhRm6YP+FO8NRpvterfqZrRt3bTn8GT5LsOTzIQgJMt4/RWLF4EKNc97
CXOSCZFn7mFNx4SzTvy23B46z9dQPfWBfTFaxU5pIa0uVWv+jFjG7l1odu0WZqBd
j0xnvXggu564CXmLz8F3draOH6XS7Ys9sTVM3Ow20MJyHtuA3hBDv+tgRhrGvNRD
MbSzTO6axNWvL46HWVEChHYlxVBCTfSQmpbcAdZOQtUfs9E4sCFrqKcRPdg7ryhY
fGbj3q0SLh55559ITttdyYE+wE4RhODgILQ3MaYZoyiL1E/4jqCOoRaFhF5R++vb
YpemcpWx7unptfOpPRRnnN4U3pqZDj4yXexcyS52Rd8BthFY/cBg8XIR42BPeVRl
OckZ+ttduvKVbvmGf+rFCSUoy1tyRwQNXzqeZTLrX+REqgFDOMVe0I49Frc2/Avw
3wIDAQABo4IBYjCCAV4wEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUzhUW
O+oCo6Zr2tkr/eWMUr56UKgwHwYDVR0jBBgwFoAUTiJUIBiV5uNu5g/6+rkS7QYX
jzkwDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD
AjB2BggrBgEFBQcBAQRqMGgwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2lj
ZXJ0LmNvbTBABggrBgEFBQcwAoY0aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29t
L0RpZ2lDZXJ0R2xvYmFsUm9vdEcyLmNydDBCBgNVHR8EOzA5MDegNaAzhjFodHRw
Oi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRHbG9iYWxSb290RzIuY3JsMB0G
A1UdIAQWMBQwCAYGZ4EMAQIBMAgGBmeBDAECAjANBgkqhkiG9w0BAQwFAAOCAQEA
bbV8m4/LCSvb0nBF9jb7MVLH/9JjHGbn0QjB4R4bMlGHbDXDWtW9pFqMPrRh2Q76
Bqm+yrrgX83jPZAcvOd7F7+lzDxZnYoFEWhxW9WnuM8Te5x6HBPCPRbIuzf9pSUT
/ozvbKFCDxxgC2xKmgp6NwxRuGcy5KQQh4xkq/hJrnnF3RLakrkUBYFPUneip+wS
BzAfK3jHXnkNCPNvKeLIXfLMsffEzP/j8hFkjWL3oh5yaj1HmlW8RE4Tl/GdUVzQ
D1x42VSusQuRGtuSxLhzBNBeJtyD//2u7wY2uLYpgK0o3X0iIJmwpt7Ovp6Bs4tI
E/peia+Qcdk9Qsr+1VgCGA==
-----END CERTIFICATE-----`,
`-----BEGIN CERTIFICATE-----
MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH
MjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI
2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx
1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQ
q2EGnI/yuum06ZIya7XzV+hdG82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5Wz
tCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9g+UQ
vIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAP
BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV
5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY
1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4
NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NG
Fdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ91
8rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTe
pLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTfl
MrY=
-----END CERTIFICATE-----`
];


context("validation_rules_google_certs", () => {
  it("validate with OCSP", async () => {

    // parse certificates into a tree
    const chain = new x509.X509CertificateTree();
    const certsTree = new x509.X509Certificates();
    pemsGoogle.forEach((pem) => certsTree.push(new x509.X509Certificate(pem)));
    chain.certificateStorage.certificates = certsTree;

    // create a validator and run the revoked rule on the tree.
    const validator = new x509.X509ChainValidator();
    validator.rules.clear();
    validator.rules.add(new x509.rules.RevokedRule());
    validator.certificateStorage.certificates = certsTree;

    // parse results
    const result = await validator.validate(certsTree[0]);
    assert(result.status === true);
  });
});