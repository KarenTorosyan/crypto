package kdf;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import util.Encoders;

public class KDFLogUtil {

    public static void logPassword(Class<?> logger, String password) {
        Logger log = LogManager.getLogger(logger);
        log.info("Password: {}", password);
    }

    public static void logSecretKey(Class<?> logger, byte[] bytes) {
        Logger log = LogManager.getLogger(logger);
        log.info("Secret key: {}", Encoders.defaultEncoder().encode(bytes));
    }
}
