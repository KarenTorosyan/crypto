package aes;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * <p>Each plaintext block is XORed with the previous ciphertext block or IV before encryption,
 * resulting in identical plaintext blocks producing non-identical ciphertext blocks.</p>
 * <a href="https://xilinx.github.io/Vitis_Libraries/security/2022.1/guide_L1/internals/cbc.html">Info</a>
 * <li>input: ByteBlocks(per 128 bit), Key(128/192/256 bit), IV(128 bit)</li>
 * <li>parallel processing possibility: sequential</li>
 * <li>data integrity: yes, except for first block</li>
 * <li>data authentication: no</li>
 */
@DisplayName("AES/CBC(Cipher Block Chaining)")
public class AES_CBC {

    private static final String PLAIN_TEXT = "FirstBlock______SecondBlock_____";
    private static final SecretKey SECRET_KEY = AESUtil.generateKey(256);
    private static final byte[] IV = AESUtil.generateIv(128);

    private byte[] encrypt(boolean padding) {
        AESLogUtil.logPlaintext(getClass(), PLAIN_TEXT);
        byte[] ciphertext = AESUtil.aesCbc(Cipher.ENCRYPT_MODE, PLAIN_TEXT.getBytes(), SECRET_KEY, IV, padding);
        AESLogUtil.logEncrypted(getClass(), ciphertext);
        return ciphertext;
    }

    private String decrypt(byte[] ciphertext, boolean padding) {
        byte[] plaintext = AESUtil.aesCbc(Cipher.DECRYPT_MODE, ciphertext, SECRET_KEY, IV, padding);
        AESLogUtil.logDecrypted(getClass(), ciphertext);
        return new String(plaintext);
    }

    @DisplayName("encrypt/decrypt")
    @Test
    void encryptDecrypt() {
        Assertions.assertEquals(decrypt(encrypt(true), true), PLAIN_TEXT);
    }

    @DisplayName("[not decrypted] before decrypt move first and second blocks")
    @Test
    void beforeDecryptMoveFirstAndSecondBytes() {
        byte[] bytes = ByteUtil.moveBytesPosition(encrypt(true), 0, 16);
        Assertions.assertThrows(Exception.class, () -> decrypt(bytes, true));
    }

    @DisplayName("before decrypt change first byte value")
    @Test
    void beforeDecryptChangeFirstByteValue() {
        byte[] bytes = encrypt(true);
        ByteUtil.changeByte(bytes, 0, (byte) 0);
        String plaintext = Assertions.assertDoesNotThrow(() -> decrypt(bytes, true));
        Assertions.assertNotEquals(plaintext, PLAIN_TEXT);
    }

    @DisplayName("[not decrypted] before decrypt change second byte value")
    @Test
    void beforeDecryptChangeSecondByteValue() {
        byte[] bytes = encrypt(true);
        ByteUtil.changeByte(bytes, 16, (byte) 0);
        Assertions.assertThrows(Exception.class, () -> decrypt(bytes, true));
    }
}
