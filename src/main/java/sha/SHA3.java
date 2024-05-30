package sha;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

public class SHA3 {

    private static final String DATA = "Data";

    @DisplayName("[SHA3-256] hash and verify")
    @Test
    void hashAndVerifySha3_256() {
        SHALogUtils.logData(getClass(), DATA);
        byte[] hash = SHAUtil.sha3(256, DATA.getBytes());
        SHALogUtils.logHash(getClass(), hash);
        boolean verified = Arrays.equals(hash, SHAUtil.sha3(256, DATA.getBytes()));
        SHALogUtils.logVerificationStatus(SHA3.class, verified);
        Assertions.assertTrue(verified);
    }

    @DisplayName("[SHA3-384] hash and verify")
    @Test
    void hashAndVerifySha3_384() {
        SHALogUtils.logData(getClass(), DATA);
        byte[] hash = SHAUtil.sha3(384, DATA.getBytes());
        SHALogUtils.logHash(getClass(), hash);
        boolean verified = Arrays.equals(hash, SHAUtil.sha3(384, DATA.getBytes()));
        SHALogUtils.logVerificationStatus(SHA3.class, verified);
        Assertions.assertTrue(verified);
    }

    @DisplayName("[SHA3-512] hash and verify")
    @Test
    void hashAndVerifySha3_512() {
        SHALogUtils.logData(getClass(), DATA);
        byte[] hash = SHAUtil.sha3(512, DATA.getBytes());
        SHALogUtils.logHash(getClass(), hash);
        boolean verified = Arrays.equals(hash, SHAUtil.sha3(512, DATA.getBytes()));
        SHALogUtils.logVerificationStatus(SHA3.class, verified);
        Assertions.assertTrue(verified);
    }
}
