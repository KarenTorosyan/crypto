package aes;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * <p>(Basic encryption mode) Each block of plaintext is encrypted independently,
 * resulting in identical plaintext blocks producing identical ciphertext blocks.</p>
 * <a href="https://xilinx.github.io/Vitis_Libraries/security/2022.1/guide_L1/internals/ecb.html">Info</a>
 * <li>input: ByteBlocks(per 128 bit), Key(128/192/256 bit)</li>
 * <li>parallel processing possibility: full</li>
 * <li>data integrity: no</li>
 * <li>data authentication: no</li>
 */
@DisplayName("AES/ECB(ElectronicBook)")
public class AES_ECB {

    private static final String PLAIN_TEXT = "FirstBlock______SecondBlock_____";
    private static final SecretKey SECRET_KEY = AESUtil.generateKey(256);

    private byte[] encrypt(boolean padding) {
        AESLogUtil.logPlaintext(getClass(), PLAIN_TEXT);
        byte[] ciphertext = AESUtil.aesEcb(Cipher.ENCRYPT_MODE, PLAIN_TEXT.getBytes(), SECRET_KEY, padding);
        AESLogUtil.logEncrypted(getClass(), ciphertext);
        return ciphertext;
    }

    private String decrypt(byte[] ciphertext, boolean padding) {
        byte[] plaintext = AESUtil.aesEcb(Cipher.DECRYPT_MODE, ciphertext, SECRET_KEY, padding);
        AESLogUtil.logDecrypted(getClass(), plaintext);
        return new String(plaintext);
    }

    @DisplayName("encrypt/decrypt")
    @Test
    void encryptDecrypt() {
        Assertions.assertEquals(decrypt(encrypt(true), true), PLAIN_TEXT);
    }

    @DisplayName("before decrypt move first and second blocks")
    @Test
    void beforeDecryptMoveFirstAndSecondBytes() {
        String plaintext = decrypt(ByteUtil.moveBytesPosition(encrypt(true), 0, 16), true);
        Assertions.assertNotEquals(plaintext, PLAIN_TEXT);
    }

    @DisplayName("before decrypt change first byte value")
    @Test
    void beforeDecryptChangeFirstByteValue() {
        byte[] bytes = encrypt(true);
        ByteUtil.changeByte(bytes, 0, (byte) 0);
        Assertions.assertNotEquals(decrypt(bytes, true), PLAIN_TEXT);
    }

    @DisplayName("before decrypt change second byte value")
    @Test
    void beforeDecryptChangeSecondByteValue() {
        byte[] bytes = encrypt(true);
        ByteUtil.changeByte(bytes, 16, (byte) 0);
        Assertions.assertNotEquals(decrypt(bytes, true), PLAIN_TEXT);
    }
}
