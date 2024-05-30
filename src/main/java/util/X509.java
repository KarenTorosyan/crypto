package util;

import dsa.DSAUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import rsa.RSAUtil;
import sha.SHAUtil;

import javax.security.auth.x500.X500Principal;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.*;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class X509 {

    private static final Logger log = LogManager.getLogger(X509.class);

    private final Path classpath = Path.of("src/main/resources");

    private final X509Service x509Service = new X509Service();

    @Test
    public void certSign() throws CertificateEncodingException {
        KeyPair issKeyPair = RSAUtil.keyPair(2048);
        String signAlg = "SHA256withRSA";

        KeyPair subKeyPair = DSAUtil.keyPair("EC", DSAUtil.P256);

        X500Principal iss = new X500PrincipalBuilder()
                .cn("X-CA")
                .o("X-Org")
                .ou("X-Department")
                .build();
        X500Principal sub = new X500PrincipalBuilder()
                .cn("servername")
                .build();

        // https://access.redhat.com/documentation/ru-ru/red_hat_certificate_system/9/html/administration_guide/standard_x.509_v3_certificate_extensions
        X509Extension issExt = new X509Extension()
                .basicConstrains(true)
                .keyUsage(6) // -> KeyUsage.choose
                .extKeyUsage(Set.of("1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"))
                .subjectKeyIdentifier(SHAUtil.sha2(256, issKeyPair.getPublic().getEncoded()))
                .subjectAltName(Set.of(
                        new X509Extension.AltName(2, "x1"), // -> GeneralName.choose
                        new X509Extension.AltName(2, "x2")))
                .authorityInfoAccess(Set.of(
                        new X509Extension.AuthorityInfoAccess("1.3.6.1.5.5.7.48.2", new X509Extension.AltName(6, "http://servername/x509/ca")), // -> AccessDescription.choose
                        new X509Extension.AuthorityInfoAccess("1.3.6.1.5.5.7.48.1", new X509Extension.AltName(6, "http://servername/x509/ocsp"))))
                .crlDistributionPoints(List.of(
                        new X509Extension.CrlDistributionPoint(
                                Set.of(new X509Extension.AltName(6, "http://servername/x509/crl")),
                                2, // -> CRLReason.choose
                                Set.of(new X509Extension.AltName(6, "http://servername/x509/ca")))))
                .certificatePolicies(Set.of("2.23.140.1.2.1"));

        Instant now = Instant.now();
        X509CrtSignParam x509SignParam = new X509CrtSignParam(iss, issKeyPair.getPrivate(), iss, issKeyPair.getPublic(), signAlg)
                .startDate(now)
                .endDate(now.plus(Duration.ofDays(1095)));
        X509Certificate issCert = x509Service.sign(x509SignParam, issExt);
        log.info("CA self-sign certificate generated for : {}", issCert.getSubjectX500Principal());
        log.info("CA self-sign certificate: {}", issCert);

        X509Extension subExt = new X509Extension()
                .basicConstrains(false)
                .keyUsage(0)
                .extKeyUsage(Set.of("1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"))
                .subjectKeyIdentifier(SHAUtil.sha2(256, issKeyPair.getPublic().getEncoded()))
                .authorityKeyIdentifier(issCert, encoded -> SHAUtil.sha2(256, encoded))
                .subjectAltName(Set.of(
                        new X509Extension.AltName(2, "x1"),
                        new X509Extension.AltName(2, "x2")))
                .issuerAltName(issCert)
                .authorityInfoAccess(Set.of(
                        new X509Extension.AuthorityInfoAccess("1.3.6.1.5.5.7.48.2", new X509Extension.AltName(6, "http://servername/x509/ca")),
                        new X509Extension.AuthorityInfoAccess("1.3.6.1.5.5.7.48.1", new X509Extension.AltName(6, "http://servername/x509/ocsp"))))
                .crlDistributionPoints(List.of(
                        new X509Extension.CrlDistributionPoint(
                                Set.of(new X509Extension.AltName(6, "http://servername/x509/crl")),
                                2,
                                Set.of(new X509Extension.AltName(6, "http://servername/x509/ca")))))
                .certificatePolicies(Set.of("2.23.140.1.2.1"));

        X509Certificate subCert = x509Service.sign(new X509CrtSignParam(iss, issKeyPair.getPrivate(), sub, subKeyPair.getPublic(), signAlg), subExt);
        log.info("Subject certificate signed for: {}", subCert.getSubjectX500Principal());
        log.info("Subject certificate signed: {}", subCert);

        Path certPath = classpath.resolve("x509ca");
        Path issCertPath = certPath.resolve("iss.crt");
        Path subCertPath = certPath.resolve("sub.crt");
        Path certChainPath = certPath.resolve("chain.crt");

        KeyFileUtil.writeX509Crt(issCertPath, issCert);
        KeyFileUtil.writeX509Crt(subCertPath, subCert);
        KeyFileUtil.writeX509CrtChain(certChainPath, new X509Certificate[]{subCert, issCert});

        Assertions.assertArrayEquals(issCert.getEncoded(), KeyFileUtil.readX509Crt(issCertPath).getEncoded());
        Assertions.assertArrayEquals(subCert.getEncoded(), KeyFileUtil.readX509Crt(subCertPath).getEncoded());

        Collection<X509Certificate> chain = KeyFileUtil.readX509CrtChain(certChainPath);
        Assertions.assertTrue(chain.containsAll(List.of(subCert, issCert)));
    }

    @DisplayName("crl sign")
    @Test
    public void crlSign() throws CRLException {
        KeyPair caKeyPair = RSAUtil.keyPair(2048);
        X500Principal iss = new X500PrincipalBuilder()
                .cn("X-CRL")
                .build();
        X509CRL crl = x509Service.signCrl(new X509CrlSignParam(iss, caKeyPair.getPrivate(), "SHA256withRSA"), Set.of());

        Path crlPath = classpath.resolve("x509ca");
        Path pemCrlPath = crlPath.resolve("crl.pem");
        Path derCrlPath = crlPath.resolve("crl.der");

        KeyFileUtil.writeX509Crl(pemCrlPath, crl, KeyFileUtil.CrlFileFormat.PEM);
        log.info("Crl written to: {}", pemCrlPath);

        KeyFileUtil.writeX509Crl(derCrlPath, crl, KeyFileUtil.CrlFileFormat.DER);
        log.info("Crl written to: {}", derCrlPath);

        X509CRL pemCrlLoaded = KeyFileUtil.readX509Crl(pemCrlPath, KeyFileUtil.CrlFileFormat.PEM);
        log.info("Crl loaded from: {}", pemCrlPath);
        Assertions.assertArrayEquals(crl.getEncoded(), pemCrlLoaded.getEncoded());

        X509CRL derCrlLoaded = KeyFileUtil.readX509Crl(derCrlPath, KeyFileUtil.CrlFileFormat.DER);
        log.info("Crl loaded from: {}", derCrlPath);
        Assertions.assertArrayEquals(crl.getEncoded(), derCrlLoaded.getEncoded());
    }

    @DisplayName("crl authentication")
    @Test
    void crlAuthentication() {
        KeyPair issKeyPair = RSAUtil.keyPair(2048);
        String signAlg = "SHA256withRSA";
        X500Principal iss = new X500PrincipalBuilder()
                .cn("X-CA")
                .build();
        X500Principal crl = new X500PrincipalBuilder()
                .cn("X-CRL")
                .build();

        X509Certificate issCert = x509Service.sign(new X509CrtSignParam(iss, issKeyPair.getPrivate(), iss, issKeyPair.getPublic(), signAlg), null);

        X509CRL genCrl = x509Service.signCrl(new X509CrlSignParam(crl, issKeyPair.getPrivate(), signAlg), Set.of());

        Assertions.assertNull(genCrl.getRevokedCertificate(issCert.getSerialNumber()));

        Set<X509CrlEntry> entries = new HashSet<>();
        entries.add(new X509CrlEntry(issCert.getSerialNumber(), Instant.now(), CRLReason.CA_COMPROMISE));
        X509CRL regenCrl = x509Service.addCrlEntry(genCrl, entries, new X509CrlSignParam(crl, issKeyPair.getPrivate(), signAlg));

        Assertions.assertNotNull(regenCrl.getRevokedCertificate(issCert.getSerialNumber()));
    }

    @DisplayName("write/read private keys")
    @Test
    void writeReadPrivateKeys() {
        writeReadPrivateKey(DSAUtil.keyPair("EC", DSAUtil.P256).getPrivate(), "ecp256.key");
        writeReadPrivateKey(DSAUtil.keyPair(DSAUtil.ED25519).getPrivate(), "ed25519.key");
        writeReadPrivateKey(DSAUtil.keyPair(DSAUtil.ED448).getPrivate(), "ed448.key");
        writeReadPrivateKey(DSAUtil.keyPair("DSA", 2048).getPrivate(), "dsa2048.key");
        writeReadPrivateKey(RSAUtil.keyPair(2048).getPrivate(), "rsa2048.key");
    }

    private void writeReadPrivateKey(PrivateKey privateKey, String filename) {
        Path path = classpath.resolve("private").resolve(filename);
        KeyFileUtil.writePrivateKey(path, privateKey, new PbeAesGcmEncipher("x-pass", null));
        log.info("Private key written to {}", path);

        PrivateKey loaded = KeyFileUtil.readPrivateKey(path, new PbeAesGcmDecipher("x-pass", null), privateKey.getAlgorithm());
        log.info("Private key loaded from {}", path);

        Assertions.assertArrayEquals(loaded.getEncoded(), privateKey.getEncoded());
    }

    @DisplayName("write/read X509 certs")
    @Test
    void writeReadX509Certs() throws CertificateEncodingException {
        writeReadX509Certs(RSAUtil.keyPair(2048), "SHA256withRSA", "rsa2048.crt");
        writeReadX509Certs(DSAUtil.keyPair("EC", DSAUtil.P256), "SHA256withECDSA", "ecp256.crt");
        writeReadX509Certs(DSAUtil.keyPair("DSA", 2048), "SHA256withDSA", "dsa2048.crt");
        writeReadX509Certs(DSAUtil.keyPair(DSAUtil.ED25519), DSAUtil.ED25519, "ed25519.crt");
        writeReadX509Certs(DSAUtil.keyPair(DSAUtil.ED448), DSAUtil.ED448, "ed448.crt");
    }

    private void writeReadX509Certs(KeyPair keyPair, String signAlg, String filename) throws CertificateEncodingException {

        X500Principal principal = new X500PrincipalBuilder()
                .cn("X-CA")
                .build();

        X509Extension ext = new X509Extension()
                .basicConstrains(true)
                .keyUsage(6)
                .extKeyUsage(Set.of("1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"))
                .subjectKeyIdentifier(SHAUtil.sha2(256, keyPair.getPublic().getEncoded()))
                .subjectAltName(Set.of(
                        new X509Extension.AltName(2, "x1"),
                        new X509Extension.AltName(2, "x2")))
                .authorityInfoAccess(Set.of(
                        new X509Extension.AuthorityInfoAccess("1.3.6.1.5.5.7.48.2", new X509Extension.AltName(6, "http://servername/x509/ca")), // -> AccessDescription.choose
                        new X509Extension.AuthorityInfoAccess("1.3.6.1.5.5.7.48.1", new X509Extension.AltName(6, "http://servername/x509/ocsp"))))
                .crlDistributionPoints(List.of(
                        new X509Extension.CrlDistributionPoint(
                                Set.of(new X509Extension.AltName(6, "http://servername/x509/crl")),
                                2,
                                Set.of(new X509Extension.AltName(6, "http://servername/x509/ca")))))
                .certificatePolicies(Set.of("2.23.140.1.2.1"));

        X509Certificate cert = x509Service.sign(new X509CrtSignParam(principal, keyPair.getPrivate(), principal, keyPair.getPublic(), signAlg), ext);

        Path path = classpath.resolve("x509").resolve(filename);
        KeyFileUtil.writeX509Crt(path, cert);
        log.info("X509 cert written to {}", path);

        X509Certificate loaded = KeyFileUtil.readX509Crt(path);
        log.info("X509 cert loaded from {}", path);

        Assertions.assertArrayEquals(loaded.getEncoded(), cert.getEncoded());
    }
}
