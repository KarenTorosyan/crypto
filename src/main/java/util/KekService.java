package util;

import aes.AESUtil;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * <a href="https://cloud.google.com/kms/docs/envelope-encryption">Envelope encryption</a>
 */
public class KekService {

    private final Map<String, byte[]> kek = new HashMap<>();

    private final Pattern cipherPattern = Pattern.compile("([a-zA-Z]{3})-([0-9]{3})(-[a-zA-Z]{3,5})?");

    public static final String DEFAULT_KEK_NAME = "kek1";

    private byte[] secretKey = getKeys().get(DEFAULT_KEK_NAME);

    public KekService(byte[] defaultSecretKey) {
        validateKeySize(defaultSecretKey.length);
        secretKey = defaultSecretKey;
    }

    private void validateKeySize(int size) {
        if (size > 256) throw new IllegalArgumentException("key length exceeds 256 bit");
    }

    public KekService() {
    }

    public void putKey(String name, byte[] key) {
        validateKeySize(key.length);
        kek.put(name, key);
    }

    public Map<String, byte[]> getKeys() {
        return kek;
    }

    public KekService secretKey(String name) {
        byte[] secretKey = getKeys().get(name);
        if (secretKey == null) {
            throw new IllegalArgumentException("Secret key not found");
        }
        this.secretKey = secretKey;
        return this;
    }

    public byte[] getSecretKey() {
        return secretKey;
    }

    public record EncryptSpec(String algorithm, int keySize, String mode) {
    }

    public EncryptSpec getSpec(String cipher) {
        Matcher matcher = cipherPattern.matcher(cipher);
        if (matcher.matches()) {
            return new EncryptSpec(matcher.group(1), Integer.parseInt(matcher.group(2)), matcher.group(3));
        } else return null;
    }

    public byte[] encrypt(String cipher, byte[] plaintext, byte[] iv, byte[] aad) {
        return operation(Cipher.ENCRYPT_MODE, cipher, plaintext, iv, aad);
    }

    public byte[] decrypt(String cipher, byte[] ciphertext, byte[] iv, byte[] aad) {
        return operation(Cipher.DECRYPT_MODE, cipher, ciphertext, iv, aad);
    }

    private byte[] operation(int mode, String cipher, byte[] plaintext, byte[] iv, byte[] aad) {
        EncryptSpec spec = getSpec(cipher);
        validateKeySize(spec.keySize());
        if (spec.algorithm().equals("AES") && spec.mode().equals("GCM")) {
            if (iv == null) {
                throw new IllegalArgumentException("IV required for GCM mode");
            }
            return AESUtil.aesGcm(mode, plaintext, aesSecretKey(secretKey), iv, 128, aad);
        }
        if (spec.algorithm().equals("AES") && spec.mode().equals("CTR")) {
            if (iv == null) {
                throw new IllegalArgumentException("IV required for CTR mode");
            }
            return AESUtil.aesCtr(mode, plaintext, aesSecretKey(secretKey), iv);
        }
        if (spec.algorithm().equals("AES") && spec.mode().equals("CBC")) {
            if (iv == null) {
                throw new IllegalArgumentException("IV required for CBC mode");
            }
            return AESUtil.aesCbc(mode, plaintext, aesSecretKey(secretKey), iv, true);
        }
        return AESUtil.aesEcb(mode, plaintext, aesSecretKey(secretKey), true);
    }

    private SecretKey aesSecretKey(byte[] key) {
        return new SecretKeySpec(key, "AES");
    }
}
