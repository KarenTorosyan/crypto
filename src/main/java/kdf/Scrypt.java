package kdf;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static kdf.KDFLogUtil.logPassword;
import static kdf.KDFLogUtil.logSecretKey;

public class Scrypt {

    @DisplayName("derive key with salt")
    @Test
    public void deriveKeyWithSalt() {
        String password = "x-pass";
        logPassword(Scrypt.class, password);
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        byte[] key = KDFUtil.scrypt(password, 256, salt);
        logSecretKey(Scrypt.class, key);
    }
}
