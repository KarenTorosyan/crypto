package dhe;

import aes.AESUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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

public class DHE {

    private static final Logger log = LogManager.getLogger(DHE.class);

    private final Queue<Map<String, String>> messages = new LinkedList<>();

    private final Encoders.Encoder encoder = Encoders.defaultEncoder();

    @DisplayName("[X25519] secret key agreement")
    @Test
    public void x25519SecretKeyAgreement() {
        KeyPair server1KeyPair = DHEUtil.keyPair(DHEUtil.X25519);
        KeyPair server2KeyPair = DHEUtil.keyPair(DHEUtil.X25519);

        write("Server1", "Server2", "Hello Server2", null,
                server1KeyPair.getPublic(), null, null);
        read("Server1", "Server2", null);

        write("Server2", "Server1", "Hello Server1", server2KeyPair.getPrivate(),
                server2KeyPair.getPublic(), "AES-256-GCM", AESUtil.generateIv(128));
        read("Server2", "Server1", server1KeyPair.getPrivate());

        write("Server1", "Server2", "...", server1KeyPair.getPrivate(),
                server1KeyPair.getPublic(), "AES-256-GCM", AESUtil.generateIv(128));
        read("Server1", "Server2", server2KeyPair.getPrivate());
    }

    private void write(String from, String to, String text, PrivateKey privateKey,
                       PublicKey nextPublicKey, String cipher, byte[] iv) {
        Map<String, String> message = new LinkedHashMap<>();
        message.put("from", from);
        message.put("to", to);
        message.put("text", text);

        if (privateKey != null || cipher != null || iv != null) {
            Map<String, String> cipherInfo = getCipherInfo(cipher);
            String algorithm = cipherInfo.get("algorithm");
            String mode = cipherInfo.get("mode");
            PublicKey prevPublicKey = getPublicKey(nextPublicKey.getAlgorithm(), fromLastMessage(to, from));
            byte[] secretKeyBytes = DHEUtil.deriveSecretKey(privateKey, prevPublicKey);
            SecretKey secretKey = secretKey(secretKeyBytes, algorithm);
            byte[] ciphertext = encrypt(text, algorithm, mode, secretKey, iv);
            message.put("text", encoder.encode(ciphertext));
            message.put("cipher", cipher);
            message.put("nonce", encoder.encode(iv));
        }
        message.put("publicKey", encoder.encode(nextPublicKey.getEncoded()));
        messages.add(message);
        log.info(json(message));
    }

    private Map<String, String> fromLastMessage(String from, String to) {
        return messages.stream()
                .filter(message -> message.get("from").equals(from) && message.get("to").equals(to))
                .toList().getLast();
    }

    private SecretKey secretKey(byte[] key, String algorithm) {
        return new SecretKeySpec(key, algorithm);
    }

    private PublicKey getPublicKey(String curve, Map<String, String> message) {
        byte[] publicKeyBytes = encoder.decode(message.get("publicKey"));
        return DHEUtil.parsePublicKey(curve, publicKeyBytes);
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

    private byte[] encrypt(String plaintext, String algorithm, String mode, SecretKey secretKey, byte[] iv) {
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

    private void read(String from, String to, PrivateKey privateKey) {
        Map<String, String> message = fromLastMessage(from, to);

        String text = message.get("text");
        if (privateKey != null && message.get("cipher") != null && message.get("nonce") != null) {
            String cipher = message.get("cipher");
            Map<String, String> cipherInfo = getCipherInfo(cipher);
            String algorithm = cipherInfo.get("algorithm");
            String mode = cipherInfo.get("mode");
            byte[] secretKeyBytes = DHEUtil.deriveSecretKey(privateKey, getPublicKey(privateKey.getAlgorithm(), message));
            SecretKey secretKey = secretKey(secretKeyBytes, algorithm);
            byte[] iv = encoder.decode(message.get("nonce"));
            byte[] ciphertext = encoder.decode(text);
            message.put("text", decrypt(ciphertext, algorithm, mode, secretKey, iv));
        }
        log.info("Read message from {} to {}: {}", from, to, message.get("text"));
    }

    private String decrypt(byte[] ciphertext, String algorithm, String mode, SecretKey secretKey, byte[] iv) {
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
