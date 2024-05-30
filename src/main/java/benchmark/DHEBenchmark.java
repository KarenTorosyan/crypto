package benchmark;

import dhe.DHEUtil;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

import java.security.KeyPair;

@State(Scope.Benchmark)
public class DHEBenchmark {

    private KeyPair dhKeyPair;
    private KeyPair ed25519KeyPair;
    private KeyPair ed448KeyPair;

    @Setup
    public void setup() {
        dhKeyPair = DHEUtil.keyPair(DHEUtil.DH);
        ed25519KeyPair = DHEUtil.keyPair(DHEUtil.X25519);
        ed448KeyPair = DHEUtil.keyPair(DHEUtil.X448);
    }

    @Benchmark
    public void DH_SECRET_KEY_DERIVATION() {
        DHEUtil.deriveSecretKey(dhKeyPair.getPrivate(), dhKeyPair.getPublic());
    }

    @Benchmark
    public void EDDHE_25519_SECRET_KEY_DERIVATION() {
        DHEUtil.deriveSecretKey(ed25519KeyPair.getPrivate(), ed25519KeyPair.getPublic());
    }

    @Benchmark
    public void EDDHE_448_SECRET_KEY_DERIVATION() {
        DHEUtil.deriveSecretKey(ed448KeyPair.getPrivate(), ed448KeyPair.getPublic());
    }
}
