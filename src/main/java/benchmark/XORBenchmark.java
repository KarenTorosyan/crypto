package benchmark;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import xor.XORUtil;

@State(Scope.Benchmark)
public class XORBenchmark {

    private byte[] plaintext;

    @Setup
    public void setup() {
        plaintext = "Plain text".getBytes();
    }

    @Benchmark
    public void XOR() {
        byte[] key = XORUtil.randomKey(plaintext.length);
        byte[] encrypted = XORUtil.encrypt(plaintext, key);
        XORUtil.encrypt(encrypted, key);
    }
}
