package benchmark;

import kdf.KDFUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

import java.security.SecureRandom;
import java.security.Security;

@State(Scope.Benchmark)
public class KDFBenchmark {

    private String password;
    private byte[] salt;
    private String secret;

    @Setup
    public void setup() {
        Security.addProvider(new BouncyCastleProvider());
        password = "x-pass";
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        this.salt = salt;
        this.secret = "secret";
    }

    @Benchmark
    public void ARGON2ID() {
        KDFUtil.argon2id(password, 256, salt, secret);
    }

    @Benchmark
    public void SCRYPT() {
        KDFUtil.scrypt(password, 256, salt);
    }

    @Benchmark
    public void BCRYPT() {
        KDFUtil.bcrypt(password, salt);
    }

    @Benchmark
    public void PBKDF2_HMAC_SHA256() {
        KDFUtil.pbkdf2WithHmacSha256(password, 256, salt);
    }
}
