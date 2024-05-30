package mac;

import aes.AESUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.Security;
import java.util.Arrays;

/**
 * Cipher-based (GMC) MAC
 */
public class GMAC {

    @BeforeAll
    static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @DisplayName("[GMAC AES] generate code and authenticate")
    @Test
    void gmacAesGenerateCodeAndAuthenticate() {
        String message = "Message";
        SecretKey secretKey = AESUtil.generateKey(128);
        byte[] iv = AESUtil.generateIv(128);
        MACLogUtils.logMessage(getClass(), message);
        byte[] mac = MACUtil.gmacAes(message.getBytes(), secretKey.getEncoded(), iv);
        MACLogUtils.logMac(getClass(), mac);
        boolean authenticated = Arrays.equals(mac, MACUtil.gmacAes(message.getBytes(), secretKey.getEncoded(), iv));
        MACLogUtils.logAuthenticationStatus(getClass(), authenticated);
        Assertions.assertTrue(authenticated);
    }
}
