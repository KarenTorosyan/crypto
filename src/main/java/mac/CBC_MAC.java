package mac;

import aes.AESUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.util.Arrays;

/**
 * Cipher-based (CBC) MAC. The mac is the last block of CBC.
 */
public class CBC_MAC {

    @DisplayName("[CBC-MAC AES] generate code and authenticate")
    @Test
    public void cbcMacAesGenerateCodeAndAuthenticate() {
        String message = "Message";
        SecretKey secretKey = AESUtil.generateKey(128);
        byte[] iv = AESUtil.generateIv(128);
        MACLogUtils.logMessage(getClass(), message);
        byte[] mac = MACUtil.cbcMacAes(message.getBytes(), secretKey.getEncoded(), iv);
        MACLogUtils.logMac(getClass(), mac);
        boolean authenticated = Arrays.equals(mac, MACUtil.cbcMacAes(message.getBytes(), secretKey.getEncoded(), iv));
        MACLogUtils.logAuthenticationStatus(getClass(), authenticated);
        Assertions.assertTrue(authenticated);
    }
}
