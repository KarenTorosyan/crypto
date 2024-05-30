package util;

import dsa.DSAUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import rsa.RSAUtil;

import javax.security.auth.x500.X500Principal;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;

public class KeyStore {

    private static final Logger log = LogManager.getLogger(KeyStoreUtil.class);

    private final Path classpath = Path.of("src/main/resources");

    private final X509Service x509Service = new X509Service();

    @DisplayName("[PKCS12] create keystore, set entries, write and read")
    @Test
    public void createKeyStoreAndSetEntryAndWriteAndRead() {
        java.security.KeyStore keyStore = KeyStoreUtil.createKeyStore("PKCS12");
        log.info("Keystore created (type: {}, provider: {})", keyStore.getType(), keyStore.getProvider());

        rsaEntry(keyStore);
        dsaEntry(keyStore);
        ecDsaEntry(keyStore);
        edDsaEntry(keyStore);

        Path keystorePath = classpath.resolve("keystore.p12");
        String keystorePassword = "x-pass";
        KeyStoreUtil.writeKeyStore(keyStore, keystorePath.toString(), keystorePassword);
        log.info("Keystore with (password: {}) write to file: {}", keystorePassword, keystorePath.toString());

        java.security.KeyStore loadedKeyStore = KeyStoreUtil.loadKeyStore(keystorePath.toString(), keystorePassword);
        log.info("Keystore with (password: {}) loaded from file: {}", keystorePassword, keystorePath);
    }

    private void rsaEntry(java.security.KeyStore keyStore) {
        KeyPair issKeyPair = RSAUtil.keyPair(2048);
        KeyPair subKeyPair = RSAUtil.keyPair(2048);
        String entryAlias = "rsa2048-key-and-cert";
        String entryPassword = "x-pass";
        Certificate[] entryCertificateChain = {
                sign(issKeyPair.getPrivate(), "SHA256withRSA", subKeyPair.getPublic())
        };
        try {
            keyStore.setKeyEntry(entryAlias, issKeyPair.getPrivate(), entryPassword.toCharArray(), entryCertificateChain);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
        logSetEntry(entryAlias, entryPassword, entryCertificateChain);
    }

    private X509Certificate sign(PrivateKey privateKey, String signAlg, PublicKey publicKey) {
        X500Principal iss = new X500PrincipalBuilder()
                .cn("X-CA")
                .build();
        X500Principal sub = new X500PrincipalBuilder()
                .cn("servername")
                .build();
        Instant now = Instant.now();
        return x509Service.sign(new X509CrtSignParam(iss, privateKey, sub, publicKey, signAlg)
                        .startDate(now)
                        .endDate(now.plus(Duration.ofDays(90))),
                null);
    }

    private void logSetEntry(String alias, String password, Certificate[] certs) {
        log.info("Set entry (alias={}, password={})", alias, password);
    }

    private void dsaEntry(java.security.KeyStore keyStore) {
        KeyPair issKeyPair = DSAUtil.keyPair("DSA", 2048);
        KeyPair subKeyPair = DSAUtil.keyPair("DSA", 2048);
        String entryAlias = "dsa2048-key-and-cert";
        String entryPassword = "x-pass";
        Certificate[] entryCertificateChain = {
                sign(issKeyPair.getPrivate(), "SHA256withDSA", subKeyPair.getPublic())
        };
        try {
            keyStore.setKeyEntry(entryAlias, issKeyPair.getPrivate(), entryPassword.toCharArray(), entryCertificateChain);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
        logSetEntry(entryAlias, entryPassword, entryCertificateChain);
    }

    private void ecDsaEntry(java.security.KeyStore keyStore) {
        KeyPair issKeyPair = DSAUtil.keyPair("EC", DSAUtil.P256);
        KeyPair subKeyPair = DSAUtil.keyPair("EC", DSAUtil.P256);
        String entryAlias = "ecp256-key-and-cert";
        String entryPassword = "x-pass";
        Certificate[] entryCertificateChain = {
                sign(issKeyPair.getPrivate(), "SHA256withECDSA", subKeyPair.getPublic())
        };
        try {
            keyStore.setKeyEntry(entryAlias, issKeyPair.getPrivate(), entryPassword.toCharArray(), entryCertificateChain);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
        logSetEntry(entryAlias, entryPassword, entryCertificateChain);
    }

    private void edDsaEntry(java.security.KeyStore keyStore) {
        KeyPair issKeyPair = DSAUtil.keyPair(DSAUtil.ED25519);
        KeyPair subKeyPair = DSAUtil.keyPair(DSAUtil.ED25519);
        String entryAlias = "ed25519-key-and-cert";
        String entryPassword = "x-pass";
        Certificate[] entryCertificateChain = {
                sign(issKeyPair.getPrivate(), DSAUtil.ED25519, subKeyPair.getPublic())
        };
        try {
            keyStore.setKeyEntry(entryAlias, issKeyPair.getPrivate(), entryPassword.toCharArray(), entryCertificateChain);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
        logSetEntry(entryAlias, entryPassword, entryCertificateChain);
    }
}
