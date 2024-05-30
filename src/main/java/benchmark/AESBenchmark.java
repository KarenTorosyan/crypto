package benchmark;

import aes.AESUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.Security;

@State(Scope.Benchmark)
public class AESBenchmark {

    private byte[] plaintext;
    private SecretKey secretKey;
    private byte[] iv;
    int tagLength;
    byte[] aad;

    @Setup
    public void setup() {
        Security.addProvider(new BouncyCastleProvider());
        plaintext = "Block___________".getBytes();
        secretKey = AESUtil.generateKey(256);
        iv = AESUtil.generateIv(128);
        tagLength = 128;
        aad = "Additional Authentication Data".getBytes();
    }

    @Benchmark
    public void AES_256_ECB() {
        byte[] ciphertext = AESUtil.aesEcb(Cipher.ENCRYPT_MODE, plaintext, secretKey, true);
        AESUtil.aesEcb(Cipher.DECRYPT_MODE, ciphertext, secretKey, true);
    }

    @Benchmark
    public void AES_256_CBC() {
        byte[] ciphertext = AESUtil.aesCbc(Cipher.ENCRYPT_MODE, plaintext, secretKey, iv, true);
        AESUtil.aesCbc(Cipher.DECRYPT_MODE, ciphertext, secretKey, iv, true);
    }

    @Benchmark
    public void AES_256_CFB() {
        byte[] ciphertext = AESUtil.aesCfb(Cipher.ENCRYPT_MODE, plaintext, secretKey, iv, false);
        AESUtil.aesCfb(Cipher.DECRYPT_MODE, ciphertext, secretKey, iv, false);
    }

    @Benchmark
    public void AES_256_OFB() {
        byte[] ciphertext = AESUtil.aesOfb(Cipher.ENCRYPT_MODE, plaintext, secretKey, iv, false);
        AESUtil.aesOfb(Cipher.DECRYPT_MODE, ciphertext, secretKey, iv, false);
    }

    @Benchmark
    public void AES_256_CTR() {
        byte[] ciphertext = AESUtil.aesCtr(Cipher.ENCRYPT_MODE, plaintext, secretKey, iv);
        AESUtil.aesCtr(Cipher.DECRYPT_MODE, ciphertext, secretKey, iv);
    }

    @Benchmark
    public void AES_256_CCM() {
        byte[] bytes = AESUtil.aesCcm(Cipher.ENCRYPT_MODE, plaintext, secretKey, iv, tagLength, aad);
        AESUtil.aesCcm(Cipher.DECRYPT_MODE, bytes, secretKey, iv, tagLength, aad);
    }

    @Benchmark
    public void AES_256_GCM() {
        byte[] bytes = AESUtil.aesGcm(Cipher.ENCRYPT_MODE, plaintext, secretKey, iv, tagLength, aad);
        AESUtil.aesGcm(Cipher.DECRYPT_MODE, bytes, secretKey, iv, tagLength, aad);
    }
}
