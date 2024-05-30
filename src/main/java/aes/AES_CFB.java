package aes;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * <p>Generates a keystream using an IV and key, which is then XORed with the plaintext to produce
 * the ciphertext. For subsequent blocks, the previous ciphertext block is used as the input to
 * the block cipher to generate the keystream for XORing with the current plaintext block.</p>
 * <a href="https://xilinx.github.io/Vitis_Libraries/security/2022.1/guide_L1/internals/cfb.html">Info</a>
 * <li>javax.Crypto implementation is CFB8(each block is 8 bit)</li>
 * <li>input: ByteStream, Key(128/192/256 bit), IV(128 bit)</li>
 * <li>parallel processing possibility: sequential</li>
 * <li>data integrity: no</li>
 * <li>data authentication: no</li>
 */
@DisplayName("AES/CFB(Cipher Feedback)")
public class AES_CFB {

    private static final String PLAIN_TEXT = "12";
    private static final SecretKey SECRET_KEY = AESUtil.generateKey(256);
    private static final byte[] IV = AESUtil.generateIv(128);

    private byte[] encrypt(boolean padding) {
        AESLogUtil.logPlaintext(getClass(), PLAIN_TEXT);
        byte[] ciphertext = AESUtil.aesCfb(Cipher.ENCRYPT_MODE, PLAIN_TEXT.getBytes(), SECRET_KEY, IV, padding);
        AESLogUtil.logEncrypted(getClass(), ciphertext);
        return ciphertext;
    }

    private String decrypt(byte[] ciphertext, boolean padding) {
        byte[] plaintext = AESUtil.aesCfb(Cipher.DECRYPT_MODE, ciphertext, SECRET_KEY, IV, padding);
        AESLogUtil.logDecrypted(getClass(), plaintext);
        return new String(plaintext);
    }

    @DisplayName("encrypt/decrypt")
    @Test
    void encryptDecrypt() {
        boolean padding = false;
        Assertions.assertEquals(decrypt(encrypt(padding), padding), PLAIN_TEXT);
    }

    @DisplayName("encrypt/decrypt with padding")
    @Test
    void encryptDecryptWithPadding() {
        boolean padding = true;
        Assertions.assertEquals(decrypt(encrypt(padding), padding), PLAIN_TEXT);
    }

    @DisplayName("before decrypt move first and second blocks")
    @Test
    void beforeDecryptMoveFirstAndSecondBytes() {
        boolean padding = false;
        String plaintext = decrypt(ByteUtil.moveBytesPosition(encrypt(padding), 0, 1), padding);
        Assertions.assertNotEquals(plaintext, PLAIN_TEXT);
    }

    @DisplayName("before decrypt change first byte value")
    @Test
    void beforeDecryptChangeFirstByteValue() {
        boolean padding = false;
        byte[] bytes = encrypt(padding);
        ByteUtil.changeByte(bytes, 0, (byte) 0);
        String plaintext = decrypt(bytes, padding);
        Assertions.assertNotEquals(plaintext, PLAIN_TEXT);
    }

    @DisplayName("before decrypt change second byte value")
    @Test
    void beforeDecryptChangeSecondByteValue() {
        boolean padding = false;
        byte[] bytes = encrypt(padding);
        ByteUtil.changeByte(bytes, 1, (byte) 0);
        String plaintext = decrypt(bytes, padding);
        Assertions.assertNotEquals(plaintext, PLAIN_TEXT);
    }
}
