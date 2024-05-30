package util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.util.HashSet;
import java.util.Set;

public class Providers {

    private static final Logger log = LogManager.getLogger(Providers.class);

    @DisplayName("cipher")
    @Test
    void cipher() {
        listFor(Cipher.class.getSimpleName());
    }

    @DisplayName("message digest")
    @Test
    void messageDigest() {
        listFor(MessageDigest.class.getSimpleName());
    }

    @DisplayName("mac")
    @Test
    void mac() {
        listFor(Mac.class.getSimpleName());
    }

    @DisplayName("mac [ BouncyCastle ]")
    @Test
    void macBouncyCastleProvider() {
        Security.addProvider(new BouncyCastleProvider());
        listFor(Mac.class.getSimpleName());
    }

    @DisplayName("signature")
    @Test
    void signature() {
        listFor(Signature.class.getSimpleName());
    }

    @DisplayName("secret key (KDF)")
    @Test
    void secretKey() {
        listFor(SecretKeyFactory.class.getSimpleName());
    }

    @DisplayName("key pair")
    @Test
    void keyPair() {
        listFor(KeyPairGenerator.class.getSimpleName());
    }

    @DisplayName("certificate")
    @Test
    void certificate() {
        listFor(CertificateFactory.class.getSimpleName());
    }

    private void listFor(String type) {
        Provider[] providers = Security.getProviders();
        Set<String> algorithms = new HashSet<>();

        for (Provider provider : providers) {
            Set<Provider.Service> services = provider.getServices();
            for (Provider.Service service : services) {
                if (service.getType().equals(type)) {
                    algorithms.add(service.getAlgorithm());
                }
            }
        }
        log.info("----- {} begin -----", type);
        for (String algorithm : algorithms) {
            log.info(algorithm);
        }
        log.info("----- {} end -----", type);
    }
}
