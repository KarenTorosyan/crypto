package benchmark;

import dsa.DSAUtil;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

import java.security.KeyPair;

@State(Scope.Benchmark)
public class DSABenchmark {

    private KeyPair dsa2048;
    private KeyPair ecp256;
    private KeyPair ecp384;
    private KeyPair ed25519;
    private KeyPair ed448;
    private String dataToSign;
    private String dsaSignatureAlgorithm;
    private String ecdsaSignatureAlgorithm;
    private String ed25519SignatureAlgorithm;
    private String ed448SignatureAlgorithm;

    @Setup
    public void setup() {
        dsa2048 = DSAUtil.keyPair("DSA", 2048);
        ecp256 = DSAUtil.keyPair("EC", DSAUtil.P256);
        ecp384 = DSAUtil.keyPair("EC", DSAUtil.P384);
        ed25519 = DSAUtil.keyPair(DSAUtil.ED25519);
        ed448 = DSAUtil.keyPair(DSAUtil.ED448);
        dataToSign = "Sign this";
        dsaSignatureAlgorithm = "SHA256WithDSA";
        ecdsaSignatureAlgorithm = "SHA256WithECDSA";
        ed25519SignatureAlgorithm = DSAUtil.ED25519;
        ed448SignatureAlgorithm = DSAUtil.ED448;
    }

    @Benchmark
    public void DSA2048_SIGN_VERIFY() {
        byte[] signature = DSAUtil.signData(dataToSign, dsaSignatureAlgorithm, dsa2048.getPrivate());
        DSAUtil.verifySignature(dataToSign, signature, dsaSignatureAlgorithm, dsa2048.getPublic());
    }

    @Benchmark
    public void ECDSA_P256_SIGN_VERIFY() {
        byte[] signature = DSAUtil.signData(dataToSign, ecdsaSignatureAlgorithm, ecp256.getPrivate());
        DSAUtil.verifySignature(dataToSign, signature, ecdsaSignatureAlgorithm, ecp256.getPublic());
    }

    @Benchmark
    public void ECDSA_P384_SIGN_VERIFY() {
        byte[] signature = DSAUtil.signData(dataToSign, ecdsaSignatureAlgorithm, ecp384.getPrivate());
        DSAUtil.verifySignature(dataToSign, signature, ecdsaSignatureAlgorithm, ecp384.getPublic());
    }

    @Benchmark
    public void EDDSA_25519_SIGN_VERIFY() {
        byte[] signature = DSAUtil.signData(dataToSign, ed25519SignatureAlgorithm, ed25519.getPrivate());
        DSAUtil.verifySignature(dataToSign, signature, ed25519SignatureAlgorithm, ed25519.getPublic());
    }

    @Benchmark
    public void EDDSA_448_SIGN_VERIFY() {
        byte[] signature = DSAUtil.signData(dataToSign, ed448SignatureAlgorithm, ed448.getPrivate());
        DSAUtil.verifySignature(dataToSign, signature, ed448SignatureAlgorithm, ed448.getPublic());
    }
}
