package sha;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

public class SHA2 {

    private static final String DATA = "Data";

    @DisplayName("[SHA-256] hash and verify")
    @Test
    void hashAndVerifySha256() {
        SHALogUtils.logData(getClass(), DATA);
        byte[] hash = SHAUtil.sha2(256, DATA.getBytes());
        SHALogUtils.logHash(getClass(), hash);
        boolean verified = Arrays.equals(hash, SHAUtil.sha2(256, DATA.getBytes()));
        SHALogUtils.logVerificationStatus(SHA2.class, verified);
        Assertions.assertTrue(verified);
    }

    @DisplayName("[SHA-384] hash and verify")
    @Test
    void hashAndVerifySha384() {
        SHALogUtils.logData(getClass(), DATA);
        byte[] hash = SHAUtil.sha2(384, DATA.getBytes());
        SHALogUtils.logHash(getClass(), hash);
        boolean verified = Arrays.equals(hash, SHAUtil.sha2(384, DATA.getBytes()));
        SHALogUtils.logVerificationStatus(SHA2.class, verified);
        Assertions.assertTrue(verified);
    }

    @DisplayName("[SHA-512] hash and verify")
    @Test
    void hashAndVerifySha512() {
        SHALogUtils.logData(getClass(), DATA);
        byte[] hash = SHAUtil.sha2(512, DATA.getBytes());
        SHALogUtils.logHash(getClass(), hash);
        boolean verified = Arrays.equals(hash, SHAUtil.sha2(512, DATA.getBytes()));
        SHALogUtils.logVerificationStatus(SHA2.class, verified);
        Assertions.assertTrue(verified);
    }
}
