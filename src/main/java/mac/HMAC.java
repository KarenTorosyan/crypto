package mac;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

/**
 * Hash-based MAC
 */
public class HMAC {

    @DisplayName("[HMAC SHA-512] generate code and authenticate")
    @Test
    void hmacSha512GenerateCodeAndAuthenticate() {
        String message = "Message";
        String secret = "Secret";
        MACLogUtils.logMessage(getClass(), message);
        byte[] mac = MACUtil.hmacSha512(message.getBytes(), secret.getBytes());
        MACLogUtils.logMac(getClass(), mac);
        boolean authenticated = Arrays.equals(mac, MACUtil.hmacSha512(message.getBytes(), secret.getBytes()));
        MACLogUtils.logAuthenticationStatus(getClass(), authenticated);
        Assertions.assertTrue(authenticated);
    }
}
