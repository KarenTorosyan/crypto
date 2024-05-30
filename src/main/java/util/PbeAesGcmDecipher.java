package util;

import aes.AESUtil;
import kdf.KDFUtil;
import org.bouncycastle.openssl.PEMDecryptor;
import org.bouncycastle.openssl.PEMException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class PbeAesGcmDecipher implements PEMDecryptor {

    private final String password;
    private String aad;

    public PbeAesGcmDecipher(String password) {
        this.password = password;
    }

    public PbeAesGcmDecipher(String password, String aad) {
        this.password = password;
        this.aad = aad;
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] iv) throws PEMException {
        SecretKey pbeSecretKey = new SecretKeySpec(KDFUtil.scrypt(password, 256, iv), "AES");
        SecretKey aesSecretKey = new SecretKeySpec(pbeSecretKey.getEncoded(), "AES");
        return AESUtil.aesGcm(Cipher.DECRYPT_MODE, ciphertext, aesSecretKey, iv,
                128, aad != null ? aad.getBytes() : null);
    }
}
