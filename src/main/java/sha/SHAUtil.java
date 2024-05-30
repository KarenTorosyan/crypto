package sha;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHAUtil {

    public static byte[] sha1(byte[] data) {
        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return messageDigest.digest(data);
    }

    public static byte[] sha2(int bit, byte[] data) {
        MessageDigest messageDigest;
        String format = switch (bit) {
            case 256 -> "SHA-256";
            case 384 -> "SHA-384";
            case 512 -> "SHA-512";
            default -> throw new IllegalStateException("Illegal size: " + bit);
        };
        try {
            messageDigest = MessageDigest.getInstance(format);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return messageDigest.digest(data);
    }

    public static byte[] sha3(int bit, byte[] data) {
        MessageDigest messageDigest;
        String format = switch (bit) {
            case 256 -> "SHA3-256";
            case 384 -> "SHA3-384";
            case 512 -> "SHA3-512";
            default -> throw new IllegalStateException("Illegal size: " + bit);
        };
        try {
            messageDigest = MessageDigest.getInstance(format);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return messageDigest.digest(data);
    }

}
