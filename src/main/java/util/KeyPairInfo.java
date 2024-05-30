package util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import dhe.DHEUtil;
import dsa.DSAUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Test;
import rsa.RSAUtil;

import java.security.KeyPair;
import java.util.LinkedHashMap;
import java.util.Map;

public class KeyPairInfo {

    private final Logger log = LogManager.getLogger(KeyPairInfo.class);

    private void log(String name, Map<String, Object> info) {
        String structuredInfo;
        try {
            structuredInfo = new ObjectMapper()
                    .writerWithDefaultPrettyPrinter()
                    .writeValueAsString(info);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        log.info("{}: {}", name, structuredInfo);
    }

    private Map<String, Object> buildInfo(KeyPair keyPair) {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("public key format: ", keyPair.getPublic().getFormat());
        info.put("public key algorithm: ", keyPair.getPublic().getAlgorithm());
        info.put("public key: ", keyPair.getPublic().getEncoded());

        info.put("private key format: ", keyPair.getPrivate().getFormat());
        info.put("private key algorithm: ", keyPair.getPrivate().getAlgorithm());
        info.put("private key: ", keyPair.getPrivate().getEncoded());
        return info;
    }

    @Test
    public void dh() {
        KeyPair keyPair = DHEUtil.keyPair(DHEUtil.DH);
        log("DH", buildInfo(keyPair));
    }

    @Test
    public void x25519() {
        KeyPair keyPair = DHEUtil.keyPair(DHEUtil.X25519);
        log("X25519", buildInfo(keyPair));
    }

    @Test
    public void x448() {
        KeyPair keyPair = DHEUtil.keyPair(DHEUtil.X448);
        log("X448", buildInfo(keyPair));
    }

    @Test
    public void ed25519() {
        KeyPair keyPair = DSAUtil.keyPair(DSAUtil.ED25519);
        log("Ed25519", buildInfo(keyPair));
    }

    @Test
    public void ed448() {
        KeyPair keyPair = DSAUtil.keyPair(DSAUtil.ED448);
        log("Ed448", buildInfo(keyPair));
    }

    @Test
    public void ecDsaP256() {
        KeyPair keyPair = DSAUtil.keyPair("EC", DSAUtil.P256);
        log("ECDSA P-256", buildInfo(keyPair));
    }

    @Test
    public void dsa2048() {
        KeyPair keyPair = DSAUtil.keyPair("DSA", 2048);
        log("DSA2048", buildInfo(keyPair));
    }

    @Test
    public void rsa2048() {
        KeyPair keyPair = RSAUtil.keyPair(2048);
        log("RSA2048", buildInfo(keyPair));
    }
}
