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
 * Cipher-based (CBC with two keys) MAC. The last block is XORed with Key1 (if the text length equals of the block length)
 * or Key2 (if not equals), then the result is encrypted.
 */
public class CMAC {

    @BeforeAll
    static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @DisplayName("[CMAC AES] generate code and authenticate")
    @Test
    void cmacAesGenerateCodeAndAuthenticate() {
        String message = "Message";
        SecretKey secretKey = AESUtil.generateKey(128);
        MACLogUtils.logMessage(getClass(), message);
        byte[] mac = MACUtil.cmacAes(message.getBytes(), secretKey.getEncoded());
        MACLogUtils.logMac(getClass(), mac);
        boolean authenticated = Arrays.equals(mac, MACUtil.cmacAes(message.getBytes(), secretKey.getEncoded()));
        MACLogUtils.logAuthenticationStatus(getClass(), authenticated);
        Assertions.assertTrue(authenticated);
    }
}
