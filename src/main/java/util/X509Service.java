package util;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;

public class X509Service {

    public X509Certificate sign(X509CrtSignParam param, X509Extension extension) {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                param.getIssuer(),
                param.getSerial(),
                Date.from(param.getStartDate()),
                Date.from(param.getEndDate()),
                param.getSubject(),
                param.getPublicKey()
        );
        if (extension != null) {
            bindExtensions(builder, extension);
        }
        X509CertificateHolder holder = builder.build(createContentSigner(param.getPrivateKey(), param.getSignAlg()));
        return convertX509Certificate(holder);
    }

    private ContentSigner createContentSigner(PrivateKey privateKey, String algorithm) {
        try {
            return new JcaContentSignerBuilder(algorithm)
                    .build(privateKey);
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        }
    }

    private X509Certificate convertX509Certificate(X509CertificateHolder holder) {
        try {
            return new JcaX509CertificateConverter().getCertificate(holder);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    private void bindExtensions(JcaX509v3CertificateBuilder builder, X509Extension extension) {
        try {
            builder.addExtension(Extension.basicConstraints, extension.isBasicConstraintCritical(), new BasicConstraints(extension.isCaCert()));
            Integer keyUsage = extension.getKeyUsage();
            if (keyUsage != null) {
                builder.addExtension(Extension.keyUsage, extension.isKeyUsageCritical(), new KeyUsage(keyUsage));
            }
            Set<String> extKeyUsage = extension.getExtKeyUsage();
            if (!extKeyUsage.isEmpty()) {
                ASN1Encodable[] asn1ObjectIdentifiers = extKeyUsage.stream()
                        .map(ASN1ObjectIdentifier::new)
                        .toArray(ASN1Encodable[]::new);
                builder.addExtension(Extension.extendedKeyUsage, extension.isExtendedKeyUsageCritical(), new DERSequence(asn1ObjectIdentifiers));
            }
            byte[] subjectKeyIdentifier = extension.getSubjectKeyIdentifier();
            if (subjectKeyIdentifier != null) {
                builder.addExtension(Extension.subjectKeyIdentifier, extension.isSubjectKeyIdentifierCritical(), new SubjectKeyIdentifier(subjectKeyIdentifier));
            }
            X509Extension.AuthorityKeyIdentifier authorityKeyIdentifier = extension.getAuthorityKeyIdentifier();
            if (authorityKeyIdentifier != null) {
                byte[] hash = authorityKeyIdentifier.hash();
                X509Extension.AltName name = authorityKeyIdentifier.name();
                BigInteger serial = authorityKeyIdentifier.serial();
                builder.addExtension(Extension.authorityKeyIdentifier, extension.isAuthorityKeyIdentifierCritical(), new AuthorityKeyIdentifier(
                        hash,
                        name == null ? null : new GeneralNames(new GeneralName(name.bitMask(), name.value())),
                        serial
                ));
            }
            Set<X509Extension.AltName> subjectAltNames = extension.getSubjectAltNames();
            if (!subjectAltNames.isEmpty()) {
                GeneralName[] names = subjectAltNames.stream()
                        .map(name -> new GeneralName(name.bitMask(), name.value()))
                        .toArray(GeneralName[]::new);
                builder.addExtension(Extension.subjectAlternativeName, extension.isSubjectAltNameCritical(), new GeneralNames(names));
            }
            Set<X509Extension.AltName> issuerAltNames = extension.getIssuerAltNames();
            if (!issuerAltNames.isEmpty()) {
                GeneralName[] names = issuerAltNames.stream()
                        .map(name -> new GeneralName(name.bitMask(), name.value()))
                        .toArray(GeneralName[]::new);
                builder.addExtension(Extension.issuerAlternativeName, extension.isIssuerAltNameCritical(), new GeneralNames(names));
            }
            Set<X509Extension.AuthorityInfoAccess> authorityInfoAccesses = extension.getAuthorityInfoAccess();
            if (!authorityInfoAccesses.isEmpty()) {
                AccessDescription[] accessDescriptions = authorityInfoAccesses.stream()
                        .filter(access -> access.accessMethodOid() != null && access.location() != null)
                        .map(access -> new AccessDescription(new ASN1ObjectIdentifier(access.accessMethodOid()), new GeneralName(access.location().bitMask(), access.location().value())))
                        .toArray(AccessDescription[]::new);
                builder.addExtension(Extension.authorityInfoAccess, extension.isAuthorityInfoAccessCritical(), new AuthorityInformationAccess(accessDescriptions));
            }
            List<X509Extension.CrlDistributionPoint> crlDistributionPoints = extension.getCrlDistributionPoints();
            DistributionPoint[] distributionPoints = new DistributionPoint[crlDistributionPoints.size()];
            if (!crlDistributionPoints.isEmpty()) {
                for (int i = 0; i < crlDistributionPoints.size(); i++) {
                    GeneralName[] pointNames = crlDistributionPoints.get(i).points()
                            .stream()
                            .map(name -> new GeneralName(name.bitMask(), name.value()))
                            .toArray(GeneralName[]::new);
                    Integer reasons = crlDistributionPoints.get(i).reasons();
                    GeneralName[] crlIssuer = crlDistributionPoints.get(i).crlIssuer()
                            .stream()
                            .map(name -> new GeneralName(name.bitMask(), name.value()))
                            .toArray(GeneralName[]::new);
                    distributionPoints[i] = new DistributionPoint(new DistributionPointName(
                            new GeneralNames(pointNames)),
                            new ReasonFlags(reasons),
                            new GeneralNames(crlIssuer));
                }
                builder.addExtension(Extension.cRLDistributionPoints, extension.isCrlDistributionPointsCritical(), new CRLDistPoint(distributionPoints));
            }
            PolicyInformation[] policies = extension.getCertificatePolicies()
                    .stream()
                    .map(oid -> new PolicyInformation(new ASN1ObjectIdentifier(oid)))
                    .toArray(PolicyInformation[]::new);
            builder.addExtension(Extension.certificatePolicies, extension.isCertificatePoliciesCritical(), new CertificatePolicies(policies));
        } catch (CertIOException e) {
            throw new RuntimeException(e);
        }
    }

    public X509CRL signCrl(X509CrlSignParam param, Set<X509CrlEntry> entries) {
        JcaX509v2CRLBuilder builder = new JcaX509v2CRLBuilder(param.getPrincipal(), Date.from(Instant.now()));
        if (!entries.isEmpty()) {
            addEntries(builder, entries);
        }
        builder.setThisUpdate(Date.from(param.getLastDate()));
        builder.setNextUpdate(Date.from(param.getNextDate()));
        X509CRLHolder holder = builder.build(createContentSigner(param.getPrivateKey(), param.getSignAlg()));
        return convertX509Crl(holder);
    }

    private void addEntries(JcaX509v2CRLBuilder builder, Set<X509CrlEntry> entries) {
        entries.forEach(entry -> builder.addCRLEntry(entry.getSerial(), Date.from(entry.getInstant()), entry.getReason().ordinal()));
    }

    private X509CRL convertX509Crl(X509CRLHolder holder) {
        try {
            return new JcaX509CRLConverter().getCRL(holder);
        } catch (CRLException e) {
            throw new RuntimeException(e);
        }
    }

    public X509CRL addCrlEntry(X509CRL crl, Set<X509CrlEntry> entries, X509CrlSignParam param) {
        JcaX509v2CRLBuilder builder = convertJcaX509v2CRLBuilder(crl);
        addEntries(builder, entries);
        builder.setThisUpdate(Date.from(param.getLastDate()));
        builder.setNextUpdate(Date.from(param.getNextDate()));
        X509CRLHolder holder = builder.build(createContentSigner(param.getPrivateKey(), param.getSignAlg()));
        return convertX509Crl(holder);
    }

    private JcaX509v2CRLBuilder convertJcaX509v2CRLBuilder(X509CRL crl) {
        try {
            return new JcaX509v2CRLBuilder(crl);
        } catch (CRLException e) {
            throw new RuntimeException(e);
        }
    }
}
