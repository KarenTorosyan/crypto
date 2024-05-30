package sha;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import util.Encoders;

public class SHALogUtils {

    public static void logData(Class<?> logger, String data) {
        Logger log = LogManager.getLogger(logger);
        log.info("data: {}", data);
    }

    public static void logHash(Class<?> logger, byte[] hash) {
        Logger log = LogManager.getLogger(logger);
        log.info("hash: {}", Encoders.defaultEncoder().encode(hash));
    }

    public static void logVerificationStatus(Class<?> logger, boolean verified) {
        Logger log = LogManager.getLogger(logger);
        if (verified) log.info("verified");
        else log.info("not verified");
    }
}
