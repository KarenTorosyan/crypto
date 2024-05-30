package kdf;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static kdf.KDFLogUtil.logPassword;
import static kdf.KDFLogUtil.logSecretKey;

public class Bcrypt {

    @DisplayName("password hashing with salt")
    @Test
    public void passwordHashingWithSalt() {
        String password = "x-pass";
        logPassword(Bcrypt.class, password);
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        byte[] key = KDFUtil.bcrypt(password, salt);
        logSecretKey(Bcrypt.class, key);
    }
}
