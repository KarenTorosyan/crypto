package benchmark;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import rsa.RSAUtil;

import java.security.KeyPair;
import java.security.SecureRandom;

@State(Scope.Benchmark)
public class RSABenchmark {

    private KeyPair keyPair2048bit;
    private KeyPair keyPair4096bit;
    private byte[] plaintext;
    private String dataToSign;
    private String signatureAlgorithm;

    @Setup
    public void setup() {
        keyPair2048bit = RSAUtil.keyPair(2048);
        keyPair4096bit = RSAUtil.keyPair(4096);
        plaintext = new byte[32];
        new SecureRandom().nextBytes(plaintext);
        dataToSign = "Sign this";
        signatureAlgorithm = "SHA1withRSA";
    }

    @Benchmark
    public void RSA2048_ENCRYPT_DECRYPT() {
        byte[] enc = RSAUtil.encrypt(plaintext, keyPair2048bit.getPublic());
        RSAUtil.decrypt(enc, keyPair2048bit.getPrivate());
    }

    @Benchmark
    public void RSA2048_SIGN_VERIFY() {
        byte[] signature = RSAUtil.signData(dataToSign, signatureAlgorithm, keyPair2048bit.getPrivate());
        RSAUtil.verifySignature(dataToSign, signature, signatureAlgorithm, keyPair2048bit.getPublic());
    }

    @Benchmark
    public void RSA4096_ENCRYPT_DECRYPT() {
        byte[] enc = RSAUtil.encrypt(plaintext, keyPair4096bit.getPublic());
        RSAUtil.decrypt(enc, keyPair4096bit.getPrivate());
    }

    @Benchmark
    public void RSA4096_SIGN_VERIFY() {
        byte[] signature = RSAUtil.signData(dataToSign, signatureAlgorithm, keyPair4096bit.getPrivate());
        RSAUtil.verifySignature(dataToSign, signature, signatureAlgorithm, keyPair4096bit.getPublic());
    }
}
