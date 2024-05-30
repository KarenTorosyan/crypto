package util;

import aes.AESUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import kdf.KDFUtil;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * KEK(Key Encryption Key) and DEK(Data Encryption Key) technique
 */
public class KekDek {

    private static final Logger log = LogManager.getLogger(KekDek.class);

    private final Encoders.Encoder encoder = Encoders.defaultEncoder();

    @DisplayName("encrypt data by DEK and encrypt dek by KEK")
    @Test
    void encryptDataByDekThenEncryptDekByKek() {
        SecretKey dekSecretKey = AESUtil.generateKey(256);
        byte[] dekIV = AESUtil.generateIv(128);
        log.info("Dek: {}", encoder.encode(dekSecretKey.getEncoded()));

        String data = "data";
        log.info("Data: {}", data);

        byte[] encData = AESUtil.aesGcm(Cipher.ENCRYPT_MODE, data.getBytes(), dekSecretKey, dekIV, 128, null);
        log.info("Encrypted Data: {}", encoder.encode(encData));

        KekService kekService = new KekService(KDFUtil.argon2id("password", 256, AESUtil.generateIv(128), "secret from secret storage"));

        byte[] encDek = kekService.encrypt("AES-256-GCM", dekSecretKey.getEncoded(), dekIV, null);
        log.info("Encrypted Dek: {}", encoder.encode(encDek));

        // store encrypted data and DEK together ...

        byte[] decDek = kekService.decrypt("AES-256-GCM", encDek, dekIV, null);
        log.info("Decrypted Dek: {}", encoder.encode(decDek));

        byte[] decData = AESUtil.aesGcm(Cipher.DECRYPT_MODE, encData, new SecretKeySpec(decDek, "AES"), dekIV, 128, null);
        log.info("Decrypted Data: {}", new String(decData));
    }
}
