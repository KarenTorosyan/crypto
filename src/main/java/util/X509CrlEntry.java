package util;

import java.math.BigInteger;
import java.security.cert.CRLReason;
import java.time.Instant;
import java.util.Objects;

public class X509CrlEntry {

    private final BigInteger serial;

    private final Instant instant;

    private final CRLReason reason;

    public X509CrlEntry(BigInteger serial, Instant instant, CRLReason reason) {
        this.serial = serial;
        this.instant = instant;
        this.reason = reason;
    }

    public BigInteger getSerial() {
        return serial;
    }

    public Instant getInstant() {
        return instant;
    }

    public CRLReason getReason() {
        return reason;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        X509CrlEntry that = (X509CrlEntry) o;
        return Objects.equals(getSerial(), that.getSerial());
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(getSerial());
    }
}
