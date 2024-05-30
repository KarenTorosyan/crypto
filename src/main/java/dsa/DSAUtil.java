package dsa;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class DSAUtil {

    // Java standard libs default EC curve is P-256 standard
    public static final ECGenParameterSpec P256 = new ECGenParameterSpec("secp256r1");

    public static final ECGenParameterSpec P384 = new ECGenParameterSpec("secp384r1");

    // Edwards-curve Digital Signature Algorithm, 256 bit, alternative of P-256
    public static final String ED25519 = ECGenParameterSpec.ED25519.getName();

    // Edwards-curve Digital Signature Algorithm, 456 bit
    public static final String ED448 = ECGenParameterSpec.ED448.getName();

    public static KeyPair keyPair(String algorithm, int bit) {
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        keyPairGenerator.initialize(bit);
        return keyPairGenerator.generateKeyPair();
    }

    public static KeyPair keyPair(String algorithm, ECGenParameterSpec curve) {
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
            keyPairGenerator.initialize(curve);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
        return keyPairGenerator.generateKeyPair();
    }

    public static KeyPair keyPair(String algorithm) {
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
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
}
