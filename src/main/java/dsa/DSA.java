package dsa;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import util.Encoders;

import java.security.KeyPair;

public class DSA {

    private final Logger log = LogManager.getLogger(DSA.class);

    private final Encoders.Encoder encoder = Encoders.defaultEncoder();

    private void logKeys(KeyPair keyPair) {
        String publicKey = encoder.encode(keyPair.getPublic().getEncoded());
        String privateKey = encoder.encode(keyPair.getPrivate().getEncoded());
        log.info("Keys: \npublic key: {}\nprivate key: {}", publicKey, privateKey);
    }

    private void logDataPreSign(String data) {
        log.info("Data: {}", data);
    }

    private void logSignature(byte[] signature) {
        log.info("Signature: {}", encoder.encode(signature));
    }

    private void logVerificationResult(boolean verify) {
        log.info("Is verified: {}", verify);
    }

    private void logChangedSignature(byte[] signature) {
        log.info("Changed Signature: {}", encoder.encode(signature));
    }

    @DisplayName("[DSA] key pair 2048 bit")
    @Test
    void dsa2048BitKeyPair() {
        KeyPair keyPair = DSAUtil.keyPair("DSA", 2048);
        logKeys(keyPair);
    }

    @DisplayName("[DSA 2048 with SHA-256] sign data and verify")
    @Test
    void signDataAndVerify() {
        String data = "Data to sign";
        logDataPreSign(data);
        KeyPair keyPair = DSAUtil.keyPair("DSA", 2048);
        String algorithm = "SHA256withDSA";
        byte[] signature = DSAUtil.signData(data, algorithm, keyPair.getPrivate());
        logSignature(signature);
        boolean verify = DSAUtil.verifySignature(data, signature, algorithm, keyPair.getPublic());
        logVerificationResult(verify);
        Assertions.assertTrue(verify);

        signature[0] = 0;
        logChangedSignature(signature);
        boolean verifyAfterChange = DSAUtil.verifySignature(data, signature, algorithm, keyPair.getPublic());
        logVerificationResult(verifyAfterChange);
        Assertions.assertFalse(verifyAfterChange);
    }

    @DisplayName("[ECDSA P-256] generate key pair 256 bit")
    @Test
    void ecDsaP256KeyPair256Bit() {
        KeyPair keyPair = DSAUtil.keyPair("EC", DSAUtil.P256);
        logKeys(keyPair);
    }

    @DisplayName("[Ed25519] generate key pair 256 bit")
    @Test
    void edDsa25519KeyPair256Bit() {
        KeyPair keyPair = DSAUtil.keyPair(DSAUtil.ED25519);
        logKeys(keyPair);
    }

    @DisplayName("[ECDSA P-256 with SHA256] sign data and verify")
    @Test
    void ecDsaP256signDataAndVerify() {
        String data = "Data to sign";
        logDataPreSign(data);
        KeyPair keyPair = DSAUtil.keyPair("EC", DSAUtil.P256);
        String algorithm = "SHA256withECDSA";
        byte[] signature = DSAUtil.signData(data, algorithm, keyPair.getPrivate());
        logSignature(signature);
        boolean verify = DSAUtil.verifySignature(data, signature, algorithm, keyPair.getPublic());
        logVerificationResult(verify);
        Assertions.assertTrue(verify);

        signature[0] = 0;
        logChangedSignature(signature);
        boolean verifyAfterChange = DSAUtil.verifySignature(data, signature, algorithm, keyPair.getPublic());
        logVerificationResult(verifyAfterChange);
        Assertions.assertFalse(verifyAfterChange);
    }

    @DisplayName("[EdDSA 25519] sign data and verify")
    @Test
    void edDsa25519SignDataAndVerify() {
        String data = "Data to sign";
        logDataPreSign(data);
        String algorithm = DSAUtil.ED25519;
        KeyPair keyPair = DSAUtil.keyPair(algorithm);
        byte[] signature = DSAUtil.signData(data, algorithm, keyPair.getPrivate());
        logSignature(signature);
        boolean verify = DSAUtil.verifySignature(data, signature, algorithm, keyPair.getPublic());
        logVerificationResult(verify);
        Assertions.assertTrue(verify);

        signature[0] = 0;
        logChangedSignature(signature);
        boolean verifyAfterChange = DSAUtil.verifySignature(data, signature, algorithm, keyPair.getPublic());
        logVerificationResult(verifyAfterChange);
        Assertions.assertFalse(verifyAfterChange);
    }
}
