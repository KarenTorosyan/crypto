package util;

import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.function.Function;

public class X509Extension {

    private boolean basicConstraintCritical = true;
    private boolean keyUsageCritical = true;
    private boolean extendedKeyUsageCritical = false;
    private boolean subjectKeyIdentifierCritical = false;
    private boolean authorityKeyIdentifierCritical = false;
    private boolean subjectAltNameCritical = false;
    private boolean issuerAltNameCritical = false;
    private boolean authorityInfoAccessCritical = false;
    private boolean crlDistributionPointsCritical = false;
    private boolean certificatePoliciesCritical = false;

    private final Map<String, Object> extensions = new HashMap<>(10);

    public X509Extension ext(String name, Object value) {
        extensions.put(name, value);
        return this;
    }

    public Object getExtension(String name) {
        return extensions.get(name);
    }

    public Object getExtensionOrDefault(String name, Object value) {
        return extensions.getOrDefault(name, value);
    }

    public X509Extension basicConstrains(boolean caCert) {
        return ext("basicConstraints", caCert);
    }

    public boolean isCaCert() {
        return (boolean) getExtensionOrDefault("basicConstraints", false);
    }

    public X509Extension basicConstraintCritical(boolean basicConstraintCritical) {
        this.basicConstraintCritical = basicConstraintCritical;
        return this;
    }

    public boolean isBasicConstraintCritical() {
        return basicConstraintCritical;
    }

    public X509Extension keyUsage(int keyUsage) {
        return ext("keyUsage", keyUsage);
    }

    public Integer getKeyUsage() {
        return (Integer) getExtension("keyUsage");
    }

    public X509Extension keyUsageCritical(boolean keyUsageCritical) {
        this.keyUsageCritical = keyUsageCritical;
        return this;
    }

    public boolean isKeyUsageCritical() {
        return keyUsageCritical;
    }

    public X509Extension extKeyUsage(Set<String> oid) {
        return ext("extKeyUsage", oid);
    }

    @SuppressWarnings("unchecked")
    public Set<String> getExtKeyUsage() {
        return (Set<String>) getExtensionOrDefault("extKeyUsage", Set.of());
    }

    public X509Extension extendedKeyUsageCritical(boolean extendedKeyUsageCritical) {
        this.extendedKeyUsageCritical = extendedKeyUsageCritical;
        return this;
    }

    public boolean isExtendedKeyUsageCritical() {
        return extendedKeyUsageCritical;
    }

    public X509Extension subjectKeyIdentifier(byte[] hash) {
        return ext("subjectKeyIdentifier", hash);
    }

    public byte[] getSubjectKeyIdentifier() {
        return (byte[]) getExtension("subjectKeyIdentifier");
    }

    public X509Extension subjectKeyIdentifierCritical(boolean subjectKeyIdentifierCritical) {
        this.subjectKeyIdentifierCritical = subjectKeyIdentifierCritical;
        return this;
    }

    public boolean isSubjectKeyIdentifierCritical() {
        return subjectKeyIdentifierCritical;
    }

    public record AltName(int bitMask, String value) {
    }

    public record AuthorityKeyIdentifier(byte[] hash, AltName name, BigInteger serial) {
    }

    public X509Extension authorityKeyIdentifier(X509Certificate cert, Function<byte[], byte[]> digest) {
        AltName name = null;
        try {
            for (List<?> san : cert.getSubjectAlternativeNames()) {
                name = new AltName((int) san.getFirst(), (String) san.getLast());
            }
        } catch (CertificateParsingException e) {
            throw new RuntimeException(e);
        }
        AuthorityKeyIdentifier aki;
        try {
            aki = new AuthorityKeyIdentifier(digest.apply(cert.getEncoded()), name, cert.getSerialNumber());
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
        return ext("authorityKeyIdentifier", aki);
    }

    public AuthorityKeyIdentifier getAuthorityKeyIdentifier() {
        return (AuthorityKeyIdentifier) getExtension("authorityKeyIdentifier");
    }

    public X509Extension authorityKeyIdentifierCritical(boolean authorityKeyIdentifierCritical) {
        this.authorityKeyIdentifierCritical = authorityKeyIdentifierCritical;
        return this;
    }

    public boolean isAuthorityKeyIdentifierCritical() {
        return authorityKeyIdentifierCritical;
    }

    public X509Extension subjectAltName(Set<AltName> names) {
        return ext("subjectAltNames", names);
    }

    @SuppressWarnings("unchecked")
    public Set<AltName> getSubjectAltNames() {
        return (Set<AltName>) getExtensionOrDefault("subjectAltNames", Set.of());
    }

    public X509Extension subjectAltNameCritical(boolean subjectAltNameCritical) {
        this.subjectAltNameCritical = subjectAltNameCritical;
        return this;
    }

    public boolean isSubjectAltNameCritical() {
        return subjectAltNameCritical;
    }

    public X509Extension issuerAltName(X509Certificate cert) {
        Set<AltName> names = new HashSet<>();
        try {
            for (List<?> san : cert.getSubjectAlternativeNames()) {
                names.add(new AltName((int) san.getFirst(), (String) san.getLast()));
            }
        } catch (CertificateParsingException e) {
            throw new RuntimeException(e);
        }
        return ext("issuerAltNames", names);
    }

    @SuppressWarnings("unchecked")
    public Set<AltName> getIssuerAltNames() {
        return (Set<AltName>) getExtensionOrDefault("issuerAltNames", Set.of());
    }

    public X509Extension issuerAltNameCritical(boolean issuerAltNameCritical) {
        this.issuerAltNameCritical = issuerAltNameCritical;
        return this;
    }

    public boolean isIssuerAltNameCritical() {
        return issuerAltNameCritical;
    }

    public record AuthorityInfoAccess(String accessMethodOid, AltName location) {
    }

    public X509Extension authorityInfoAccess(Set<AuthorityInfoAccess> aia) {
        return ext("authorityInfoAccess", aia);
    }

    @SuppressWarnings("unchecked")
    public Set<AuthorityInfoAccess> getAuthorityInfoAccess() {
        return (Set<AuthorityInfoAccess>) getExtensionOrDefault("authorityInfoAccess", Set.of());
    }

    public X509Extension authorityInfoAccessCritical(boolean authorityInfoAccessCritical) {
        this.authorityInfoAccessCritical = authorityInfoAccessCritical;
        return this;
    }

    public boolean isAuthorityInfoAccessCritical() {
        return authorityInfoAccessCritical;
    }

    public record CrlDistributionPoint(Set<AltName> points, Integer reasons, Set<AltName> crlIssuer) {
    }

    public X509Extension crlDistributionPoints(List<CrlDistributionPoint> cdp) {
        return ext("crlDistributionPoints", cdp);
    }

    @SuppressWarnings("unchecked")
    public List<CrlDistributionPoint> getCrlDistributionPoints() {
        return (List<CrlDistributionPoint>) getExtension("crlDistributionPoints");
    }

    public X509Extension crlDistributionPointsCritical(boolean crlDistributionPointsCritical) {
        this.crlDistributionPointsCritical = crlDistributionPointsCritical;
        return this;
    }

    public boolean isCrlDistributionPointsCritical() {
        return crlDistributionPointsCritical;
    }

    public X509Extension certificatePolicies(Set<String> policyOid) {
        return ext("certificatePolicies", policyOid);
    }

    @SuppressWarnings("unchecked")
    public Set<String> getCertificatePolicies() {
        return (Set<String>) getExtensionOrDefault("certificatePolicies", Set.of());
    }

    public X509Extension certificatePoliciesCritical(boolean certificatePoliciesCritical) {
        this.certificatePoliciesCritical = certificatePoliciesCritical;
        return this;
    }

    public boolean isCertificatePoliciesCritical() {
        return certificatePoliciesCritical;
    }
}
