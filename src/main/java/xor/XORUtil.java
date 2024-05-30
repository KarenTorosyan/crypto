package xor;

import java.security.SecureRandom;

public class XORUtil {

    public static byte[] encrypt(byte[] text, byte[] key) {
        byte[] bytes = new byte[text.length];
        for (int i = 0; i < text.length; i++) {
            bytes[i] = (byte) (text[i] ^ key[i]);
        }
        return bytes;
    }

    public static byte[] randomKey(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }
}
