package mac;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import util.Encoders;

public class MACLogUtils {

    public static void logMessage(Class<?> logger, String message) {
        Logger log = LogManager.getLogger(logger);
        log.info("message: {}", message);
    }

    public static void logMac(Class<?> logger, byte[] mac) {
        Logger log = LogManager.getLogger(logger);
        log.info("mac: {}", Encoders.hex().encode(mac));
    }

    public static void logAuthenticationStatus(Class<?> logger, boolean authenticated) {
        Logger log = LogManager.getLogger(logger);
        if (authenticated) {
            log.info("authenticated");
        } else {
            log.info("unauthenticated");
        }
    }
}
