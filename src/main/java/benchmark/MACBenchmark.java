package benchmark;

import aes.AESUtil;
import mac.MACUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

import java.security.Security;

@State(Scope.Benchmark)
public class MACBenchmark {

    private byte[] message;
    private byte[] key;
    private byte[] key128bit;
    private byte[] iv;

    @Setup
    public void setup() {
        Security.addProvider(new BouncyCastleProvider());
        message = "Message".getBytes();
        key = "Key from secret storage".getBytes();
        key128bit = AESUtil.generateKey(128).getEncoded();
        iv = AESUtil.generateIv(128);
    }

    @Benchmark
    public void HMAC_SHA512() {
        MACUtil.hmacSha512(message, key);
    }

    @Benchmark
    public void CBC_MAC_AES() {
        MACUtil.cbcMacAes(message, key128bit, iv);
    }

    @Benchmark
    public void CMAC_AES_CBC() {
        MACUtil.cmacAes(message, key128bit);
    }

    @Benchmark
    public void GMAC_AES_GCM() {
        MACUtil.gmacAes(message, key128bit, iv);
    }

    @Benchmark
    public void KMAC_128() {
        MACUtil.kmac(message, key, 128);
    }

    @Benchmark
    public void KMAC_256() {
        MACUtil.kmac(message, key, 256);
    }
}
