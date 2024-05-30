package rsa;

import aes.AESUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import util.Encoders;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RSA {

    private static final Logger log = LogManager.getLogger(RSA.class);

    private final Queue<Map<String, String>> messages = new LinkedList<>();

    private final Encoders.Encoder encoder = Encoders.defaultEncoder();

    @DisplayName("generate key pair 2048 bit")
    @Test
    void generateKeyPair2048Bit() {
        KeyPair keyPair = RSAUtil.keyPair(2048);
        String publicKey = encoder.encode(keyPair.getPublic().getEncoded());
        String privateKey = encoder.encode(keyPair.getPrivate().getEncoded());
        log.info("Keys: \npublic key: {}\nprivate key: {}", publicKey, privateKey);
    }

    @DisplayName("[RSA 2048 with SHA-256] sign data and verify")
    @Test
    void signDataAndVerify() {
        String data = "Data to sign";
        log.info("Data: {}", data);
        KeyPair keyPair = RSAUtil.keyPair(2048);
        String algorithm = "SHA256withRSA";
        byte[] signature = RSAUtil.signData(data, algorithm, keyPair.getPrivate());
        log.info("Signature: {}", encoder.encode(signature));
        boolean verify = RSAUtil.verifySignature(data, signature, algorithm, keyPair.getPublic());
        log.info("Is verified: {}", verify);
        Assertions.assertTrue(verify);

        signature[0] = 0;
        log.info("Changed Signature: {}", encoder.encode(signature));
        boolean verifyAfterChange = RSAUtil.verifySignature(data, signature, algorithm, keyPair.getPublic());
        log.info("Is verified: {}", verifyAfterChange);
        Assertions.assertFalse(verifyAfterChange);
    }

    @DisplayName("secret key exchange")
    @Test
    public void secretKeyExchange() {
        KeyPair server1KeyPair = RSAUtil.keyPair(2048);
        KeyPair server2KeyPair = RSAUtil.keyPair(2048);

        write("Server1", "Server2", "Hello Server2",
                server1KeyPair.getPublic(), null, null);
        read("Server1", "Server2", null);

        write("Server2", "Server1", "Hello Server1",
                server2KeyPair.getPublic(), "AES-256-GCM", AESUtil.generateIv(128));
        read("Server2", "Server1", server1KeyPair.getPrivate());

        write("Server1", "Server2", "...",
                server1KeyPair.getPublic(), "AES-256-GCM", AESUtil.generateIv(128));
        read("Server1", "Server2", server2KeyPair.getPrivate());
    }

    private void write(String from, String to, String text, PublicKey publicKey, String cipher, byte[] iv) {
        Map<String, String> message = new LinkedHashMap<>();
        message.put("from", from);
        message.put("to", to);
        message.put("text", text);
        if (cipher != null && iv != null) {
            SecretKey secretKey = generateSecretKey(cipher);
            PublicKey prevPublicKey = getPublicKey(fromLastMessage(to, from));
            byte[] encryptedSecretKey = encryptSecretKey(secretKey, prevPublicKey);
            message.put("secretKey", encoder.encode(encryptedSecretKey));
            message.put("text", encoder.encode(encrypt(text, cipher, secretKey, iv)));
            message.put("cipher", cipher);
            message.put("nonce", encoder.encode(iv));
        }
        message.put("publicKey", encoder.encode(publicKey.getEncoded()));
        messages.add(message);
        log.info(json(message));
    }

    private PublicKey getPublicKey(Map<String, String> message) {
        byte[] publicKeyBytes = encoder.decode(message.get("publicKey"));
        return RSAUtil.parsePublicKey(publicKeyBytes);
    }

    private SecretKey generateSecretKey(String cipher) {
        Map<String, String> cipherInfo = getCipherInfo(cipher);
        int keySize = Integer.parseInt(cipherInfo.get("keySize"));
        return AESUtil.generateKey(keySize);
    }

    private byte[] encryptSecretKey(SecretKey secretKey, PublicKey publicKey) {
        return RSAUtil.encrypt(secretKey.getEncoded(), publicKey);
    }

    private byte[] decryptSecretKey(byte[] encryptedSecretKey, PrivateKey privateKey) {
        return RSAUtil.decrypt(encryptedSecretKey, privateKey);
    }

    private Map<String, String> getCipherInfo(String cipher) {
        Pattern pattern = Pattern.compile("([a-zA-Z]{3})-([0-9]{3})-([a-zA-Z]{3})");
        Matcher matcher = pattern.matcher(cipher);
        Map<String, String> info = new HashMap<>();
        if (matcher.matches()) {
            info.put("algorithm", matcher.group(1).toUpperCase());
            info.put("keySize", matcher.group(2));
            info.put("mode", matcher.group(3).toUpperCase());
        }
        return info;
    }

    private byte[] encrypt(String plaintext, String cipher, SecretKey secretKey, byte[] iv) {
        Map<String, String> cipherInfo = getCipherInfo(cipher);
        String algorithm = cipherInfo.get("algorithm");
        String mode = cipherInfo.get("mode");
        if (algorithm.equals("AES") && mode.equals("GCM")) {
            return AESUtil.aesGcm(Cipher.ENCRYPT_MODE, plaintext.getBytes(), secretKey, iv,
                    128, null);
        }
        if (algorithm.equals("AES") && mode.equals("CBC")) {
            return AESUtil.aesCbc(Cipher.ENCRYPT_MODE, plaintext.getBytes(), secretKey, iv, true);
        }
        return AESUtil.aesEcb(Cipher.ENCRYPT_MODE, plaintext.getBytes(), secretKey, true);
    }

    private String json(Map<String, String> message) {
        try {
            return new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(message);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    private SecretKey getSecretKey(Map<String, String> message, PrivateKey privateKey) {
        String cipher = message.get("cipher");
        String algorithm = getCipherInfo(cipher).get("algorithm");
        byte[] encryptedSecretKey = encoder.decode(message.get("secretKey"));
        byte[] decryptedSecretKey = decryptSecretKey(encryptedSecretKey, privateKey);
        return new SecretKeySpec(decryptedSecretKey, algorithm);
    }

    private void read(String from, String to, PrivateKey privateKey) {
        Map<String, String> message = fromLastMessage(from, to);
        String text = message.get("text");
        if (privateKey != null && message.get("cipher") != null && message.get("nonce") != null) {
            String cipher = message.get("cipher");
            SecretKey secretKey = getSecretKey(message, privateKey);
            byte[] iv = encoder.decode(message.get("nonce"));
            text = decrypt(encoder.decode(text), cipher, secretKey, iv);
        }
        log.info("Read message from {} to {}: {}", from, to, text);
    }

    private Map<String, String> fromLastMessage(String from, String to) {
        return messages.stream()
                .filter(message -> message.get("from").equals(from) && message.get("to").equals(to))
                .toList().getLast();
    }

    private String decrypt(byte[] ciphertext, String cipher, SecretKey secretKey, byte[] iv) {
        Map<String, String> cipherInfo = getCipherInfo(cipher);
        String algorithm = cipherInfo.get("algorithm");
        String mode = cipherInfo.get("mode");
        if (algorithm.equals("AES") && mode.equals("GCM")) {
            return new String(AESUtil.aesGcm(Cipher.DECRYPT_MODE, ciphertext, secretKey, iv,
                    128, null));
        }
        if (algorithm.equals("AES") && mode.equals("CBC")) {
            return new String(AESUtil.aesCbc(Cipher.DECRYPT_MODE, ciphertext, secretKey, iv, true));
        }
        return new String(AESUtil.aesEcb(Cipher.DECRYPT_MODE, ciphertext, secretKey, true));
    }
}
