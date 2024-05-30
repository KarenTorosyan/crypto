package kdf;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static kdf.KDFLogUtil.logPassword;
import static kdf.KDFLogUtil.logSecretKey;

public class Argon2id {

    @DisplayName("password hashing with salt")
    @Test
    void passwordHashingWithSalt() {
        String password = "x-pass";
        logPassword(Argon2id.class, password);
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        byte[] bytes = KDFUtil.argon2id(password, 256, salt, null);
        logSecretKey(Argon2id.class, bytes);
    }

    @DisplayName("password hashing with salt and secret")
    @Test
    void passwordHashingWithSaltAndSecret() {
        String password = "x-pass";
        logPassword(Argon2id.class, password);
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        String secret = "secret from secret storage";
        byte[] bytes = KDFUtil.argon2id(password, 256, salt, secret);
        logSecretKey(Argon2id.class, bytes);
    }
}
