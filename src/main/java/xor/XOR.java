package xor;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import util.Encoders;

public class XOR {

    private static final Logger log = LogManager.getLogger(XOR.class);

    @DisplayName("encrypt/decrypt")
    @Test
    void encryptDecrypt() {
        String plaintext = "Text";
        byte[] key = XORUtil.randomKey(plaintext.length());

        log.info("plaintext: {}", plaintext);

        byte[] encrypted = XORUtil.encrypt(plaintext.getBytes(), key);
        log.info("encrypted: {}", Encoders.defaultEncoder().encode(encrypted));

        byte[] decrypted = XORUtil.encrypt(encrypted, key);
        log.info("decrypted: {}", new String(decrypted));
    }
}
