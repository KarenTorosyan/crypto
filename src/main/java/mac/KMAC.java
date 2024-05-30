package mac;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.Security;
import java.util.Arrays;

/**
 * Keccak-based MAC
 */
public class KMAC {

    @BeforeAll
    static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    private void kmac(int bit) {
        String message = "Message";
        String secret = "Secret";
        MACLogUtils.logMessage(getClass(), message);
        byte[] mac = MACUtil.kmac(message.getBytes(), secret.getBytes(), bit);
        MACLogUtils.logMac(getClass(), mac);
        boolean authenticated = Arrays.equals(mac, MACUtil.kmac(message.getBytes(), secret.getBytes(), bit));
        MACLogUtils.logAuthenticationStatus(getClass(), authenticated);
        Assertions.assertTrue(authenticated);
    }

    @DisplayName("[KMAC-128] generate code and authenticate")
    @Test
    void kmac128GenerateCodeAndAuthenticate() {
        kmac(128);
    }

    @DisplayName("[KMAC-256] generate code and authenticate")
    @Test
    void kmac256GenerateCodeAndAuthenticate() {
        kmac(256);
    }
}
