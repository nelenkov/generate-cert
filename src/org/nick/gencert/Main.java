
package org.nick.gencert;

import org.bouncycastle.x509.X509V3CertificateGenerator;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;

import javax.security.auth.x500.X500Principal;

@SuppressWarnings("deprecation")
public class Main {

    private static SecureRandom random = new SecureRandom();

    private static final int RSA_KEY_SIZE = 2048;
    private static final String KEY_ALIAS = "key";

    public static X509Certificate generateSelfSignedCertificate(
            KeyPair keyPair, String subject, String issuer) throws Exception {
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        certGen.setPublicKey(keyPair.getPublic());
        certGen.setSerialNumber(generateSerial());
        X500Principal subjectPrincipal = new X500Principal(subject);
        X500Principal issuerPrincipal = new X500Principal(issuer);
        certGen.setSubjectDN(subjectPrincipal);
        certGen.setIssuerDN(issuerPrincipal);
        Calendar cal = Calendar.getInstance();
        certGen.setNotBefore(cal.getTime());
        cal.add(Calendar.YEAR, 10);
        certGen.setNotAfter(cal.getTime());
        certGen.setSignatureAlgorithm("SHA256WithRSA");

        X509Certificate cert = certGen.generate(keyPair.getPrivate());

        return cert;
    }

    private static BigInteger generateSerial() {
        return BigInteger.valueOf(Math.abs(random.nextLong()));
    }

    public static KeyStore createKeyStore(String subject, X509Certificate issuer, String password)
            throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(RSA_KEY_SIZE);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        X509Certificate cert = generateSelfSignedCertificate(keyPair, subject, 
            issuer.getSubjectDN().getName());

        ks.setKeyEntry(KEY_ALIAS, keyPair.getPrivate(), password.toCharArray(),
                new X509Certificate[] {
                        cert, issuer
                });

        return ks;
    }

    private static File persistKeyStore(String path, KeyStore ks, String password)
            throws Exception {
        File ksFile = new File(path);
        FileOutputStream fos = new FileOutputStream(ksFile);
        ks.store(fos, password == null ? null : password.toCharArray());

        return ksFile;
    }

    private static byte[] readFile(String path) throws Exception {
        FileInputStream fis = new FileInputStream(path);
        byte[] result = new byte[fis.available()];
        fis.read(result);
        fis.close();

        return result;
    }

    private static X509Certificate parseCert(byte[] blob) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X509");

        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(blob));
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 4) {
            System.out
                    .println("generate-cert <issuer cert> <DN> <keystore path> <keystore password>");
            System.exit(1);
        }

        String certPath = args[0];
        String dn = args[1];
        String ksPath = args[2];
        String ksPassword = args[3];

        X509Certificate issuer = parseCert(readFile(certPath));
        KeyStore ks = createKeyStore(dn, issuer, ksPassword);
        File ksFile = persistKeyStore(ksPath, ks, ksPassword);
        System.out.println("Saved keystore to: " + ksFile.getAbsolutePath());
    }
}
