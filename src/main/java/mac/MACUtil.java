package mac;

import aes.AESUtil;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

public class MACUtil {

    public static byte[] hmac(byte[] message, byte[] key, String hashFunc) {
        String algorithm = "Hmac".concat(hashFunc.toUpperCase());
        Mac mac;
        try {
            mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(key, algorithm));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return mac.doFinal(message);
    }

    public static byte[] hmacSha512(byte[] message, byte[] key) {
        return hmac(message, key, "SHA512");
    }

    public static byte[] cbcMacAes(byte[] message, byte[] key, byte[] iv) {
        SecretKeySpec aesSecretKey = new SecretKeySpec(key, "AES");
        byte[] enc = AESUtil.aesCbc(Cipher.ENCRYPT_MODE, message, aesSecretKey, iv, true);
        return Arrays.copyOfRange(enc, enc.length - 16, enc.length);
    }

    public static byte[] cmacAes(byte[] message, byte[] key, String algorithm, String provider) {
        Mac mac;
        try {
            mac = Mac.getInstance(algorithm, provider);
            mac.init(new SecretKeySpec(key, "AES"));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return mac.doFinal(message);
    }

    public static byte[] cmacAes(byte[] message, byte[] key) {
        return cmacAes(message, key, "AESCMAC", "BC");
    }

    public static byte[] gmacAes(byte[] message, byte[] key, byte[] iv, String algorithm, String provider) {
        Mac mac;
        try {
            mac = Mac.getInstance(algorithm, provider);
            mac.init(new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return mac.doFinal(message);
    }

    public static byte[] gmacAes(byte[] message, byte[] key, byte[] iv) {
        return gmacAes(message, key, iv, "AES-GMAC", "BC");
    }

    public static byte[] kmac(byte[] message, byte[] key, String algorithm, String provider) {
        Mac mac;
        try {
            mac = Mac.getInstance(algorithm, provider);
            mac.init(new SecretKeySpec(key, algorithm));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return mac.doFinal(message);
    }

    public static byte[] kmac(byte[] message, byte[] key, int bit) {
        if (bit != 128 && bit != 256) {
            throw new RuntimeException("KMAC length must be 128 or 256 bit");
        }
        return kmac(message, key, "KMAC" + bit, "BC");
    }
}
