package kdf;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.SecureRandom;

import static kdf.KDFLogUtil.logPassword;
import static kdf.KDFLogUtil.logSecretKey;

@DisplayName("PBKDF2(Password-Based Key Derivation Function 2)")
public class PBKDF2 {

    @DisplayName("[PBKDF2 HMacSHA256] derive key with salt")
    @Test
    void deriveKeyWithSalt() {
        String password = "x-pass";
        logPassword(PBKDF2.class, password);
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        SecretKey secretKey = KDFUtil.pbkdf2WithHmacSha256(password, 256, salt);
        logSecretKey(PBKDF2.class, secretKey.getEncoded());
    }
}
