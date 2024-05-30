package util;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyStore;

public class KeyStoreUtil {

    public static KeyStore createKeyStore(String type) {
        try {
            KeyStore keyStore = KeyStore.getInstance(type);
            keyStore.load(null, null);
            return keyStore;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void writeKeyStore(KeyStore keyStore, String path, String password) {
        try (FileOutputStream fileOutputStream = new FileOutputStream(path)) {
            keyStore.store(fileOutputStream, password.toCharArray());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static KeyStore loadKeyStore(String path, String password) {
        try {
            return KeyStore.getInstance(new File(path), password.toCharArray());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
