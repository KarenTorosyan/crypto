package aes;

import mac.MACUtil;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class AESUtil {

    public static SecretKey generateKey(int bit) {
        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        keyGenerator.init(bit);
        return keyGenerator.generateKey();
    }

    public static byte[] generateIv(int bit) {
        byte[] ivBytes = new byte[bit / 8];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(ivBytes);
        return ivBytes;
    }

    public static byte[] ivJoin(byte[] ciphertext, byte[] iv) {
        byte[] extendedCiphertext = new byte[ciphertext.length + iv.length];
        System.arraycopy(iv, 0, extendedCiphertext, 0, iv.length);
        System.arraycopy(ciphertext, 0, extendedCiphertext, iv.length, ciphertext.length);
        return extendedCiphertext;
    }

    public static byte[] ivFrom(byte[] extendedCiphertext, int ivLength) {
        byte[] iv = new byte[ivLength];
        System.arraycopy(extendedCiphertext, 0, iv, 0, ivLength);
        return iv;
    }

    private static byte[] ciphertextFrom(byte[] extendedCiphertext, int ivLength) {
        byte[] ciphertext = new byte[extendedCiphertext.length - ivLength];
        System.arraycopy(extendedCiphertext, ivLength, ciphertext, 0, ciphertext.length);
        return ciphertext;
    }

    public record IvCiphertextHolder(byte[] iv, byte[] ciphertext) {
    }

    public static IvCiphertextHolder ivSplit(byte[] extendedCiphertext, int ivLength) {
        return new IvCiphertextHolder(ivFrom(extendedCiphertext, ivLength), ciphertextFrom(extendedCiphertext, ivLength));
    }

    public static byte[] aesEcb(int op, byte[] content, SecretKey secretKey, boolean padding) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/" + (padding ? "PKCS5Padding" : "NoPadding"));
            cipher.init(op, secretKey);
            return cipher.doFinal(content);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] aesCbc(int op, byte[] content, SecretKey secretKey, byte[] iv, boolean padding) {
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/" + (padding ? "PKCS5Padding" : "NoPadding"));
            cipher.init(op, secretKey, ivParameterSpec);
            return cipher.doFinal(content);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] aesCfb(int op, byte[] content, SecretKey secretKey, byte[] iv, boolean padding) {
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        try {
            Cipher cipher = Cipher.getInstance("AES/CFB/" + (padding ? "PKCS5Padding" : "NoPadding"));
            cipher.init(op, secretKey, ivParameterSpec);
            return cipher.doFinal(content);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] aesOfb(int op, byte[] content, SecretKey secretKey, byte[] iv, boolean padding) {
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        try {
            Cipher cipher = Cipher.getInstance("AES/OFB/" + (padding ? "PKCS5Padding" : "NoPadding"));
            cipher.init(op, secretKey, ivParameterSpec);
            return cipher.doFinal(content);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] aesCtr(int op, byte[] content, SecretKey secretKey, byte[] iv) {
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding"); // padding isn't supported
            cipher.init(op, secretKey, ivParameterSpec);
            return cipher.doFinal(content);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] aesCcm(int op, byte[] content, SecretKey secretKey, byte[] iv, int tagLength, byte[] aad) {
        int tagLengthAsBytes = tagLength / 8;

        if (op == Cipher.ENCRYPT_MODE) {

            if (aad != null) {
                byte[] plaintextWithAad = new byte[content.length + aad.length];
                System.arraycopy(content, 0, plaintextWithAad, 0, content.length);
                System.arraycopy(aad, 0, plaintextWithAad, content.length, aad.length);
                content = plaintextWithAad;
            }

            byte[] ciphertext = aesCtr(op, content, secretKey, iv);

            byte[] mac = MACUtil.cbcMacAes(ciphertext, secretKey.getEncoded(), iv);

            byte[] ciphertextWithMac = new byte[ciphertext.length + mac.length];
            System.arraycopy(ciphertext, 0, ciphertextWithMac, 0, ciphertext.length);
            System.arraycopy(mac, 0, ciphertextWithMac, ciphertext.length, mac.length);

            return ciphertextWithMac;

        } else if (op == Cipher.DECRYPT_MODE) {
            byte[] ciphertext = new byte[content.length - tagLengthAsBytes];
            System.arraycopy(content, 0, ciphertext, 0, ciphertext.length);

            byte[] mac = new byte[tagLengthAsBytes];
            System.arraycopy(content, content.length - tagLengthAsBytes, mac, 0, mac.length);

            if (!Arrays.equals(mac, MACUtil.cbcMacAes(ciphertext, secretKey.getEncoded(), iv))) {
                throw new RuntimeException("Unauthenticated");
            }

            byte[] plaintext = aesCtr(op, ciphertext, secretKey, iv);

            if (aad != null) {
                byte[] aadFrom = new byte[aad.length];
                System.arraycopy(plaintext, plaintext.length - aad.length, aadFrom, 0, aad.length);
                if (!Arrays.equals(aad, aadFrom)) {
                    throw new RuntimeException("Invalid AAD");
                }
                byte[] plaintextFrom = new byte[plaintext.length - aad.length];
                System.arraycopy(plaintext, 0, plaintextFrom, 0, plaintextFrom.length);
                return plaintextFrom;
            }
            return plaintext;

        } else {
            throw new IllegalArgumentException("Unsupported operation: " + op);
        }
    }

    public static byte[] aesCcm(int op, byte[] content, SecretKey secretKey, byte[] iv, int tagLength, byte[] aad, String provider) {
        if (provider == null) {
            return aesCcm(op, content, secretKey, iv, tagLength, aad);
        }
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(tagLength, iv);
        try {
            Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", provider); // padding isn't supported on AEAD mode
            cipher.init(op, secretKey, gcmParameterSpec);
            if (aad != null) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(content);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] aesGcm(int op, byte[] content, SecretKey secretKey, byte[] iv, int tagLength, byte[] aad) {
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(tagLength, iv);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); // padding isn't supported on AEAD mode
            cipher.init(op, secretKey, gcmParameterSpec);
            if (aad != null) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(content);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
