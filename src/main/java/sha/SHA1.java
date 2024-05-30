package sha;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

public class SHA1 {

    @DisplayName("hash and verify")
    @Test
    public void hashAndVerify() {
        String data = "Data";
        SHALogUtils.logData(getClass(), data);
        byte[] hash = SHAUtil.sha1(data.getBytes());
        SHALogUtils.logHash(getClass(), hash);
        boolean verified = Arrays.equals(hash, SHAUtil.sha1(data.getBytes()));
        SHALogUtils.logVerificationStatus(SHA1.class, verified);
        Assertions.assertTrue(verified);
    }
}
