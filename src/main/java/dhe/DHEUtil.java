package dhe;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class DHEUtil {

    public static final ECGenParameterSpec DH = new ECGenParameterSpec("DH");

    // XDH(Extended Diffie-Hellman), Ephemeral, 256 bit, recommended curve for key agreement by OWASP
    public static final ECGenParameterSpec X25519 = new ECGenParameterSpec(ECGenParameterSpec.X25519.getName());

    // XDH(Extended Diffie-Hellman), Ephemeral, 456 bit
    public static final ECGenParameterSpec X448 = new ECGenParameterSpec(ECGenParameterSpec.X448.getName());

    public static KeyPair dhKeyPair(int bit) {
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("DH");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        keyPairGenerator.initialize(bit);
        return keyPairGenerator.generateKeyPair();
    }

    public static KeyPair keyPair(ECGenParameterSpec ecGenParameterSpec) {
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(ecGenParameterSpec.getName());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return keyPairGenerator.generateKeyPair();
    }

    public static KeyAgreement keyAgreement(PrivateKey privateKey) {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance(privateKey.getAlgorithm());
            keyAgreement.init(privateKey);
            return keyAgreement;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] deriveSecretKey(PrivateKey privateKey, PublicKey publicKey) {
        KeyAgreement keyAgreement = keyAgreement(privateKey);
        try {
            keyAgreement.doPhase(publicKey, true);
            return keyAgreement.generateSecret();
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static PublicKey parsePublicKey(String algorithm, byte[] bytes) {
        try {
            return KeyFactory.getInstance(algorithm).generatePublic(new X509EncodedKeySpec(bytes));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
