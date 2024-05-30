package util;

import aes.AESUtil;
import kdf.KDFUtil;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.PEMException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class PbeAesGcmEncipher implements PEMEncryptor {

    private final String password;
    private final byte[] iv = AESUtil.generateIv(128);
    private String aad;

    PbeAesGcmEncipher(String password) {
        this.password = password;
    }

    public PbeAesGcmEncipher(String password, String aad) {
        this.password = password;
        this.aad = aad;
    }

    @Override
    public String getAlgorithm() {
        return "AES-256-GCM";
    }

    @Override
    public byte[] getIV() {
        return iv;
    }

    @Override
    public byte[] encrypt(byte[] plaintext) throws PEMException {
        SecretKey pbeSecretKey = new SecretKeySpec(KDFUtil.scrypt(password, 256, iv), "AES");
        SecretKey aesSecretKey = new SecretKeySpec(pbeSecretKey.getEncoded(), "AES");
        return AESUtil.aesGcm(Cipher.ENCRYPT_MODE, plaintext, aesSecretKey, iv,
                128, aad != null ? aad.getBytes() : null);
    }
}
