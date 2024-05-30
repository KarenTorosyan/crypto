package util;

import org.bouncycastle.openssl.PEMDecryptor;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemHeader;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.function.Function;

// Java NIO + BouncyCastle
public class KeyFileUtil {

    private static final Function<PEMEncryptor, List<PemHeader>> pemHeaders = encryptor ->
            List.of(
                    new PemHeader("Proc-Type", "4,ENCRYPTED"),
                    new PemHeader("DEK-Info", String.join(",",
                            encryptor.getAlgorithm(),
                            HexFormat.of().withUpperCase().formatHex(encryptor.getIV())))
            );

    public static void writePrivateKey(Path path, PrivateKey privateKey, PEMEncryptor encryptor) {
        createDirectories(path);
        try (Writer writer = Files.newBufferedWriter(path);
             PemWriter pemWriter = new PemWriter(writer)) {
            pemWriter.writeObject(new PemObject("ENCRYPTED PRIVATE KEY",
                    pemHeaders.apply(encryptor),
                    encryptor.encrypt(privateKey.getEncoded())));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void createDirectories(Path path) {
        try {
            Files.createDirectories(path.getParent());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static PrivateKey readPrivateKey(Path path, PEMDecryptor decryptor, String algorithm) {
        try (Reader reader = Files.newBufferedReader(path);
             PEMParser pemReader = new PEMParser(reader)) {
            PemObject pemObject = pemReader.readPemObject();
            PemHeader pemHeader = (PemHeader) pemObject.getHeaders().get(1);
            String ivHex = pemHeader.getValue().split(",")[1];
            byte[] iv = HexFormat.of().parseHex(ivHex);
            byte[] dec = decryptor.decrypt(pemObject.getContent(), iv);

            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(dec));

        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static void writeX509Crt(Path path, X509Certificate cert) {
        createDirectories(path);
        try (Writer writer = Files.newBufferedWriter(path);
             PemWriter pemWriter = new PemWriter(writer)) {
            pemWriter.writeObject(new PemObject("CERTIFICATE", cert.getEncoded()));
        } catch (IOException | CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public static void writeX509CrtChain(Path path, X509Certificate[] x509Certificates) {
        deleteFileIfExists(path);
        createDirectories(path);
        try (Writer writer = Files.newBufferedWriter(path,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
             PemWriter pemWriter = new PemWriter(writer)) {
            for (X509Certificate x509Certificate : x509Certificates) {
                pemWriter.writeObject(new PemObject("CERTIFICATE", x509Certificate.getEncoded()));
            }
        } catch (IOException | CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    private static void deleteFileIfExists(Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static X509Certificate readX509Crt(Path path) {
        try (Reader reader = Files.newBufferedReader(path);
             PemReader pemReader = new PemReader(reader)) {
            PemObject pemObject = pemReader.readPemObject();
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(pemObject.getContent()));
        } catch (IOException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public static Collection<X509Certificate> readX509CrtChain(Path path) {
        try (Reader reader = Files.newBufferedReader(path);
             PemReader pemReader = new PemReader(reader)) {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            Collection<X509Certificate> certificates = new ArrayList<>();
            while (true) {
                PemObject pemObject = pemReader.readPemObject();
                if (pemObject == null) {
                    break;
                }
                X509Certificate certificate = (X509Certificate) certFactory
                        .generateCertificate(new ByteArrayInputStream(pemObject.getContent()));
                certificates.add(certificate);
            }
            return certificates;
        } catch (IOException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public enum CrlFileFormat {
        PEM, DER
    }

    public static void writeX509Crl(Path path, X509CRL x509CRL, CrlFileFormat crlFileFormat) {
        createDirectories(path);
        if (crlFileFormat == CrlFileFormat.PEM) {
            try (Writer writer = Files.newBufferedWriter(path);
                 PemWriter pemWriter = new PemWriter(writer)) {
                pemWriter.writeObject(new PemObject("X509 CRL", x509CRL.getEncoded()));
            } catch (IOException | CRLException e) {
                throw new RuntimeException(e);
            }
        } else {
            try {
                Files.write(path, x509CRL.getEncoded());
            } catch (IOException | CRLException e) {
                throw new RuntimeException(e);
            }
        }
    }

    public static X509CRL readX509Crl(Path path, CrlFileFormat crlFileFormat) {
        createDirectories(path);
        CertificateFactory certificateFactory;
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
        if (crlFileFormat == CrlFileFormat.PEM) {
            try (Reader reader = Files.newBufferedReader(path);
                 PemReader pemReader = new PemReader(reader)) {
                PemObject pemObject = pemReader.readPemObject();
                return (X509CRL) certificateFactory.generateCRL(new ByteArrayInputStream(pemObject.getContent()));
            } catch (IOException | CRLException e) {
                throw new RuntimeException(e);
            }
        } else {
            try (InputStream inputStream = new BufferedInputStream(new FileInputStream(path.toFile()))) {
                return (X509CRL) certificateFactory.generateCRL(inputStream);
            } catch (IOException | CRLException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
