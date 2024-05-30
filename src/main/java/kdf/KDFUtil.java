package kdf;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.generators.BCrypt;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.params.Argon2Parameters;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * <a href="https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html">OWASP</a>
 */
public class KDFUtil {

    /**
     * <p>Java standard libs have no support of Argon2, switching to BouncyCastle lib.</p>
     * <p>Argon2id is a password-hashing algorithm that is designed to securely hash passwords and protect against
     * various types of attacks, including brute-force, side-channel, and memory-timing attacks</p>
     * <p>Argon2id is a hybrid version of Argon2 that combines the Argon2i and Argon2d variants. Argon2i is
     * optimized to resist side-channel attacks, while Argon2d is faster and resistant to GPU-based attacks.
     * Argon2id aims to provide both security against side-channel attacks and high performance.</p>
     * <p>m=19456 (19 MiB), t=2, p=1 == m=47104 (46 MiB), t=1, p=1</p>
     */
    public static byte[] argon2id(String password, int bit, byte[] salt, String secret) {
        Argon2BytesGenerator generator = new Argon2BytesGenerator();

        Argon2Parameters.Builder parameters = new Argon2Parameters.Builder()
                .withVersion(Argon2Parameters.ARGON2_id)
                .withMemoryAsKB(19456)
                .withIterations(2)
                .withParallelism(1);

        if (salt == null) {
            throw new IllegalArgumentException("Salt required!");
        }
        parameters.withSalt(salt);

        if (secret != null) {
            parameters.withSecret(secret.getBytes());
        }

        generator.init(parameters.build());
        byte[] hash = new byte[bit / 8];
        generator.generateBytes(password.toCharArray(), hash);
        return hash;
    }

    /**
     * <p>Java standard libs have no support of Scrypt, switching to BouncyCastle lib.</p>
     * <p>Scrypt is a password-based key derivation function (PBKDF) that is designed to be more secure against
     * hardware brute-force attacks than alternative functions such as Bcrypt or PBKDF2.</p>
     * <p>N=2^17 (128 MiB), r=8 (1024 bytes), p=1</p>
     */
    public static byte[] scrypt(String password, int bit, byte[] salt) {
        if (salt == null) {
            throw new IllegalArgumentException("Salt required!");
        }
        return SCrypt.generate(password.getBytes(), salt, 128, 8, 1, bit / 8);
    }

    /**
     * <p>Java standard libs have no support of Bcrypt, switching to BouncyCastle lib.</p>
     * <p>The bcrypt password hashing function should be the best choice for password storage in legacy systems
     * or if PBKDF2 is required to achieve FIPS-140 compliance.</p>
     * <p>The work factor should be as large as verification server performance will allow, with a minimum of 10.</p>
     */
    public static byte[] bcrypt(String password, byte[] salt) { // fixed 192 bit
        if (password.getBytes().length > 72) {
            throw new IllegalArgumentException("Password max length is 72");
        }
        if (salt == null) {
            throw new IllegalArgumentException("Salt required!");
        }
        return BCrypt.generate(password.getBytes(), salt, 10);
    }

    /**
     * <p>Since PBKDF2 is recommended by NIST and has FIPS-140 validated implementations, so it should be
     * the preferred algorithm when these are required.</p>
     * <p>The PBKDF2 algorithm requires that you select an internal hashing algorithm such as an HMAC or a
     * variety of other hashing algorithms. HMAC-SHA-256 is widely supported and is recommended by NIST.</p>
     * <p>The work factor for PBKDF2 is implemented through an iteration count, which should set differently
     * based on the internal hashing algorithm used.</p>
     * <p>PBKDF2-HMAC-SHA256: 600,000 iterations & parallel PPBKDF2-SHA256: cost 5</p>
     */
    public static SecretKey pbkdf2WithHmacSha256(String password, int bit, byte[] salt) {
        SecretKeyFactory secretKeyFactory;
        if (salt == null) {
            throw new IllegalArgumentException("Salt required!");
        }
        try {
            secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Illegal algorithm", e);
        }
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, 600000, bit);
        try {
            return secretKeyFactory.generateSecret(pbeKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException("Illegal PBE key spec", e);
        }
    }
}
