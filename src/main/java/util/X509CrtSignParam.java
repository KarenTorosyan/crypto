package util;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;

public class X509CrtSignParam {

    private final X500Principal issuer;
    private final PrivateKey privateKey;

    private final X500Principal subject;
    private final PublicKey publicKey;

    private final String signAlg;

    private BigInteger serial;
    private Instant startDate;
    private Instant endDate;

    public X509CrtSignParam(X500Principal issuer, PrivateKey privateKey, X500Principal subject, PublicKey publicKey, String signAlg) {
        this.issuer = issuer;
        this.privateKey = privateKey;
        this.subject = subject;
        this.publicKey = publicKey;
        this.signAlg = signAlg;
    }

    public X509CrtSignParam serial(BigInteger serial) {
        this.serial = serial;
        return this;
    }

    public BigInteger getSerial() {
        return serial != null ? serial : new BigInteger(256, new SecureRandom());
    }

    public X509CrtSignParam startDate(Instant startDate) {
        this.startDate = startDate;
        return this;
    }

    public Instant getStartDate() {
        return startDate != null ? startDate : Instant.now();
    }

    public X509CrtSignParam endDate(Instant endDate) {
        this.endDate = endDate;
        return this;
    }

    public Instant getEndDate() {
        return endDate != null ? endDate : getStartDate().plus(Duration.ofDays(90));
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public X500Principal getIssuer() {
        return issuer;
    }

    public X500Principal getSubject() {
        return subject;
    }

    public String getSignAlg() {
        return signAlg;
    }
}
