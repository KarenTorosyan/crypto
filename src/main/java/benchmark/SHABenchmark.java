package benchmark;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import sha.SHAUtil;

@State(Scope.Benchmark)
public class SHABenchmark {

    private byte[] data;

    @Setup
    public void setup() {
        data = "Data".getBytes();
    }

    @Benchmark
    public void SHA1() {
        SHAUtil.sha2(256, data);
    }

    @Benchmark
    public void SHA2_256() {
        SHAUtil.sha2(256, data);
    }

    @Benchmark
    public void SHA2_384() {
        SHAUtil.sha2(384, data);
    }

    @Benchmark
    public void SHA2_512() {
        SHAUtil.sha2(512, data);
    }

    @Benchmark
    public void SHA3_256() {
        SHAUtil.sha3(256, data);
    }

    @Benchmark
    public void SHA3_384() {
        SHAUtil.sha3(384, data);
    }

    @Benchmark
    public void SHA3_512() {
        SHAUtil.sha3(512, data);
    }
}
