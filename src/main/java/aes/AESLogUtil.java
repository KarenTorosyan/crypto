package aes;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import util.Encoders;

public class AESLogUtil {

    public static void logPlaintext(Class<?> logger, String plaintext) {
        Logger log = LogManager.getLogger(logger);
        log.info("plaintext: {}", plaintext);
    }

    public static void logEncrypted(Class<?> logger, byte[] ciphertext) {
        Logger log = LogManager.getLogger(logger);
        log.info("encrypted: {}", Encoders.defaultEncoder().encode(ciphertext));
    }

    public static void logDecrypted(Class<?> logger, byte[] ciphertext) {
        Logger log = LogManager.getLogger(logger);
        log.info("decrypted: {}", new String(ciphertext));
    }
}
