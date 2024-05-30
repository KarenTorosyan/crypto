package aes;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.Security;

/**
 * <p>Combines CTR for encryption and CBC-MAC for authentication.</p>
 * <a href="https://xilinx.github.io/Vitis_Libraries/security/2022.1/guide_L1/internals/ccm.html">Info</a>
 * <li>input: ByteStream, Key(128/192/256 bit), IV(128 bit), TagLength(32, 48, 64, 80, 96, 112, 128 bit)</li>
 * <li>parallel processing possibility: parallel encryption, sequential hashing</li>
 * <li>data integrity: yes</li>
 * <li>data authentication: yes</li>
 */
@DisplayName("AES/CCM(Counter with CBC-MAC)")
public class AES_CCM {

    private static final String PLAIN_TEXT = "12";
    private static final SecretKey SECRET_KEY = AESUtil.generateKey(256);
    private static final byte[] IV = AESUtil.generateIv(128);
    private static final int TAG_LENGTH = 128;

    @BeforeAll
    static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    private byte[] encrypt(String aad) {
        AESLogUtil.logPlaintext(getClass(), PLAIN_TEXT);
        byte[] ciphertext = AESUtil.aesCcm(Cipher.ENCRYPT_MODE, PLAIN_TEXT.getBytes(), SECRET_KEY, IV,
                TAG_LENGTH, aad != null ? aad.getBytes() : null);
        AESLogUtil.logEncrypted(getClass(), ciphertext);
        return ciphertext;
    }

    private String decrypt(byte[] ciphertext, String aad) {
        byte[] plaintext = AESUtil.aesCcm(Cipher.DECRYPT_MODE, ciphertext, SECRET_KEY, IV,
                TAG_LENGTH, aad != null ? aad.getBytes() : null);
        AESLogUtil.logDecrypted(getClass(), plaintext);
        return new String(plaintext);
    }

    @DisplayName("encrypt/decrypt")
    @Test
    void encryptDecrypt() {
        Assertions.assertEquals(decrypt(encrypt(null), null), PLAIN_TEXT);
    }

    @DisplayName("encrypt/decrypt with aad")
    @Test
    void encryptDecryptWithAad() {
        String aad = "Additional Authentication Data";
        Assertions.assertEquals(decrypt(encrypt(aad), aad), PLAIN_TEXT);
    }

    @DisplayName("[not decrypted] when aad incorrect")
    @Test
    void decryptionErrorWhenAadIncorrect() {
        String aad = "Additional Authentication Data";
        byte[] bytes = encrypt(aad);
        Assertions.assertThrows(Exception.class, () -> decrypt(bytes, aad.substring(0, aad.length() - 1)));
    }

    @DisplayName("[not decrypted] before decrypt move first and second blocks")
    @Test
    void beforeDecryptMoveFirstAndSecondBytes() {
        byte[] bytes = ByteUtil.moveBytesPosition(encrypt(null), 0, 1);
        Assertions.assertThrows(Exception.class, () -> decrypt(bytes, null));
    }

    @DisplayName("[not decrypted] before decrypt change first byte value")
    @Test
    void beforeDecryptChangeFirstByteValue() {
        byte[] bytes = encrypt(null);
        ByteUtil.changeByte(bytes, 0, (byte) 0);
        Assertions.assertThrows(Exception.class, () -> decrypt(bytes, null));
    }

    @DisplayName("[not decrypted] before decrypt change second byte value")
    @Test
    void beforeDecryptChangeSecondByteValue() {
        byte[] bytes = encrypt(null);
        ByteUtil.changeByte(bytes, 1, (byte) 0);
        Assertions.assertThrows(Exception.class, () -> decrypt(bytes, null));
    }
}
