package rsa;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class RSAUtil {

    public static KeyPair keyPair(int bit) {
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        keyPairGenerator.initialize(bit);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] signData(String data, String algorithm, PrivateKey privateKey) {
        try {
            Signature signature = Signature.getInstance(algorithm);
            signature.initSign(privateKey);
            signature.update(data.getBytes());
            return signature.sign();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static boolean verifySignature(String data, byte[] signature, String algorithm, PublicKey publicKey) {
        try {
            Signature signatureO = Signature.getInstance(algorithm);
            signatureO.initVerify(publicKey);
            signatureO.update(data.getBytes());
            return signatureO.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    public static byte[] encrypt(byte[] plaintext, PublicKey publicKey) {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] decrypt(byte[] ciphertext, PrivateKey privateKey) {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static PublicKey parsePublicKey(byte[] bytes) {
        try {
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
