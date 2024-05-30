package aes;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * <p>Encrypting a counter value for each block of plaintext,
 * which is then XORed with the plaintext to produce the ciphertext.
 * The counter value is incremented for each subsequent block.</p>
 * <a href="https://xilinx.github.io/Vitis_Libraries/security/2022.1/guide_L1/internals/ctr.html">Info</a>
 * <li>input: ByteStream, Key(128/192/256 bit), IV(128 bit)</li>
 * <li>parallel processing possibility: full</li>
 * <li>data integrity: no</li>
 * <li>data authentication: no</li>
 */
@DisplayName("AES/CTR(Counter)")
public class AES_CTR {

    private static final String PLAIN_TEXT = "12";
    private static final SecretKey SECRET_KEY = AESUtil.generateKey(256);
    private static final byte[] IV = AESUtil.generateIv(128);

    private byte[] encrypt() {
        AESLogUtil.logPlaintext(getClass(), PLAIN_TEXT);
        byte[] ciphertext = AESUtil.aesCtr(Cipher.ENCRYPT_MODE, PLAIN_TEXT.getBytes(), SECRET_KEY, IV);
        AESLogUtil.logEncrypted(getClass(), ciphertext);
        return ciphertext;
    }

    private String decrypt(byte[] ciphertext) {
        byte[] plaintext = AESUtil.aesCtr(Cipher.ENCRYPT_MODE, ciphertext, SECRET_KEY, IV);
        AESLogUtil.logDecrypted(getClass(), plaintext);
        return new String(plaintext);
    }

    @DisplayName("encrypt/decrypt")
    @Test
    void encryptDecrypt() {
        Assertions.assertEquals(decrypt(encrypt()), PLAIN_TEXT);
    }

    @DisplayName("before decrypt move first and second blocks")
    @Test
    void beforeDecryptMoveFirstAndSecondBytes() {
        String plaintext = decrypt(ByteUtil.moveBytesPosition(encrypt(), 0, 1));
        Assertions.assertNotEquals(plaintext, PLAIN_TEXT);
    }

    @DisplayName("before decrypt change first byte value")
    @Test
    void beforeDecryptChangeFirstByteValue() {
        byte[] bytes = encrypt();
        ByteUtil.changeByte(bytes, 0, (byte) 0);
        Assertions.assertNotEquals(decrypt(bytes), PLAIN_TEXT);
    }

    @DisplayName("before decrypt change second byte value")
    @Test
    void beforeDecryptChangeSecondByteValue() {
        byte[] bytes = encrypt();
        ByteUtil.changeByte(bytes, 1, (byte) 0);
        Assertions.assertNotEquals(decrypt(bytes), PLAIN_TEXT);
    }
}
