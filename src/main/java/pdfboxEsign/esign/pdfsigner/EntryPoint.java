package pdfboxEsign.esign.pdfsigner;

import java.security.KeyPair;
import java.security.cert.Certificate;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
public class EntryPoint {
  static private String keystorePath = "/Users/kishansaini/Downloads/PeopleHum/dev-document-signing.p12";
  static private String keystoreType = "PKCS12";
  static private String keystorePassword = "password";
  static private String certificateAlias = "f5df6ad2fa05f53a665559c8296a2e05538d3354";
  static private KeyPair keyPair;
  static private Certificate[] certificateChain;

  public static void main(String[] args) throws Exception{
    cacheRequiredDetails();
    SignThePdf signThePdf=new SignThePdf(contentSigner(), "http://timestamp.entrust.net/TSS/RFC3161sha2TS", certificateChain);
//    signThePdf.signThePdf(
//        new File("/Users/kishansaini/Downloads/Signme/unsigned/unsignedPdf.pdf"),
//        new File("/Users/kishansaini/Downloads/Signme/signed/signedPdf.pdf"));
//
//    signThePdf.signPreviouslySignedPdf(
//        new File("/Users/kishansaini/Downloads/Signme/pdfs/first5filled.pdf"),
//        new File("/Users/kishansaini/Downloads/Signme/signthepdf/signedPdf.pdf"));

    signThePdf.signPreviouslySignedPdf(
        new File("/Users/kishansaini/Downloads/Signme/signthepdf/signedPdf.pdf"),
        new File("/Users/kishansaini/Downloads/Signme/finalTry/signedPdf.pdf"));
  }


  static ContentSigner contentSigner() throws OperatorCreationException {
    return new JcaContentSignerBuilder("SHA256WITHRSA")
        .build(keyPair.getPrivate());
  }

  static void cacheRequiredDetails() throws Exception {
    try(InputStream inputStream = new FileInputStream(keystorePath)) {
      Security.addProvider(new BouncyCastleProvider());
      char[] password = keystorePassword.toCharArray();

      KeyStore keyStore = KeyStore.getInstance(keystoreType, "BC");
      keyStore.load(inputStream, password);

      PrivateKey privateKey = (PrivateKey) keyStore.getKey(certificateAlias, password);

      Certificate cert = keyStore.getCertificate(certificateAlias);
      PublicKey publicKey = cert.getPublicKey();

      keyPair = new KeyPair(publicKey, privateKey);
      certificateChain = keyStore.getCertificateChain(certificateAlias);
      if (certificateChain == null) {
        // cert chain is not available construct it our self
        certificateChain = constructCertChain(keyStore, certificateAlias).
            toArray(new Certificate[0]);
      }
    } catch (IOException e) {
      log.error("Failed to load certificate from file {}", keystorePath, e);
      throw e;
    } catch (CertificateException | KeyStoreException | NoSuchAlgorithmException | NoSuchProviderException | UnrecoverableEntryException e) {
      log.error("Failed to extract keypair and certificate from file {}", keystorePath, e);
      throw e;
    }
  }

  public static List<X509Certificate> constructCertChain(KeyStore keyStore, String certificateAlias) throws KeyStoreException {
    Map<X500Principal, X509Certificate> certMap = fetchAllAliasesFrom(keyStore);

    List<X509Certificate> chain = new ArrayList<>();
    X509Certificate cert = (X509Certificate) keyStore.getCertificate(certificateAlias);
    chain.add(cert);

    while (true) {
      X500Principal subject = cert.getSubjectX500Principal();
      X500Principal issuer = cert.getIssuerX500Principal();
      cert = certMap.get(issuer);
      if (subject.equals(issuer) || cert == null) {
        // we have found the root of cert chain
        // or full chain is not available in the keystore
        break;
      }
      chain.add(cert);
    }
    return chain;
  }

  public static Map<X500Principal, X509Certificate> fetchAllAliasesFrom(KeyStore keyStore) throws KeyStoreException {
    Map<X500Principal, X509Certificate> certMap = new HashMap<>();
    Enumeration<String> enumeration = keyStore.aliases();
    while (enumeration.hasMoreElements()) {
      String alias = enumeration.nextElement();
      X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
      certMap.put(cert.getSubjectX500Principal(), cert);
    }
    return certMap;
  }

}
