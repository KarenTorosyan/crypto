package util;

import javax.security.auth.x500.X500Principal;
import java.security.PrivateKey;
import java.time.Duration;
import java.time.Instant;

public class X509CrlSignParam {

    private final X500Principal principal;

    private final PrivateKey privateKey;

    private final String signAlg;

    private Instant lastDate;

    private Instant nextDate;

    public X509CrlSignParam(X500Principal principal, PrivateKey privateKey, String signAlg) {
        this.principal = principal;
        this.privateKey = privateKey;
        this.signAlg = signAlg;
    }

    public X500Principal getPrincipal() {
        return principal;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public String getSignAlg() {
        return signAlg;
    }

    public X509CrlSignParam lastDate(Instant lastDate) {
        this.lastDate = lastDate;
        return this;
    }

    public Instant getLastDate() {
        return lastDate != null ? lastDate : Instant.now();
    }

    public X509CrlSignParam nextDate(Instant nextDate) {
        this.nextDate = nextDate;
        return this;
    }

    public Instant getNextDate() {
        return nextDate != null ? nextDate : Instant.now().plus(Duration.ofDays(30));
    }
}
