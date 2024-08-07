import { OCSPResponse } from "./ocsp";
import { X509Certificate } from "./x509_cert";
import { X509Certificates } from "./x509_certs";

export interface IResult<T> {
  target: ICertificateStorageHandler;
  result: T;
  error?: Error;
}

export type RevocationType = "crl" | "ocsp";

export interface ICertificateStorageHandler {

  parent: ICertificateStorageHandler | null;

  /**
   * Returns issuer certificate or certificates
   * @param cert Issued certificate
   * @returns Issuer certificates
   */
  findIssuers(cert: X509Certificate, crypto?: Crypto): Promise<X509Certificates>;

  findCertificate(responderID: string | ArrayBuffer): Promise<X509Certificate[]>;
  /**
   * Returns true if certificate is trusted
   */
  isTrusted(cert: X509Certificate): Promise<IResult<boolean>>;

  /**
   * Returns the latest OCSP response for the certificate
   */
  findOCSP(cert: X509Certificate): Promise<IResult<OCSPResponse | null>>;

}

export interface ICertificateStorage {
  certificateStorage: ICertificateStorageHandler;
}