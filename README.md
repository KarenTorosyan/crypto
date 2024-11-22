## Cryptography Standards

Cryptography algorithms and X.509

### Benchmark

Help `java -jar benchmarks.jar -h`

Benchmark all `java -jar benchmarks.jar .* -i 5 -r 3 -wi 5 -w 3 -f 1 -t 1 -bm thrpt`

Or `java -jar benchmarks.jar AESB SHAB MACB KDFB DSAB RSAB DHEB -i 5 -r 3 -wi 5 -w 3 -f 1 -t 1 -bm thrpt`

List benchmarks with parameters `java -jar benchmarks.jar -lp`

### Benchmark results

#### forks: 1, threads: 1, iterations: 5(3s each), warmup iterations: 5(3s each)

    Benchmark                                        Mode  Cnt        Score       Error  Units
    AESBenchmark.AES_256_CBC                        thrpt    5   186417.851 ±  1024.605  ops/s
    AESBenchmark.AES_256_CCM                        thrpt    5    91156.269 ±   210.556  ops/s
    AESBenchmark.AES_256_CFB                        thrpt    5   187195.634 ±   338.347  ops/s
    AESBenchmark.AES_256_CTR                        thrpt    5   198577.533 ±   778.410  ops/s
    AESBenchmark.AES_256_ECB                        thrpt    5   201111.502 ±  1318.825  ops/s
    AESBenchmark.AES_256_GCM                        thrpt    5   227176.645 ±  1721.527  ops/s
    AESBenchmark.AES_256_OFB                        thrpt    5   182127.025 ±   833.276  ops/s
    DHEBenchmark.DH_SECRET_KEY_DERIVATION           thrpt    5     1085.328 ±     3.780  ops/s
    DHEBenchmark.EDDHE_25519_SECRET_KEY_DERIVATION  thrpt    5     6406.802 ±   169.766  ops/s
    DHEBenchmark.EDDHE_448_SECRET_KEY_DERIVATION    thrpt    5     1836.794 ±     9.984  ops/s
    DSABenchmark.DSA2048_SIGN_VERIFY                thrpt    5      844.780 ±     4.918  ops/s
    DSABenchmark.ECDSA_P256_SIGN_VERIFY             thrpt    5     1167.626 ±     3.500  ops/s
    DSABenchmark.ECDSA_P384_SIGN_VERIFY             thrpt    5      273.116 ±     6.153  ops/s
    DSABenchmark.EDDSA_25519_SIGN_VERIFY            thrpt    5      730.910 ±     4.519  ops/s
    DSABenchmark.EDDSA_448_SIGN_VERIFY              thrpt    5      211.108 ±     2.043  ops/s
    KDFBenchmark.ARGON2ID                           thrpt    5       36.721 ±     0.402  ops/s
    KDFBenchmark.BCRYPT                             thrpt    5       18.744 ±     0.061  ops/s
    KDFBenchmark.PBKDF2_HMAC_SHA256                 thrpt    5        2.116 ±     0.010  ops/s
    KDFBenchmark.SCRYPT                             thrpt    5     2800.307 ±    15.070  ops/s
    MACBenchmark.CBC_MAC_AES                        thrpt    5   372890.638 ±  1263.068  ops/s
    MACBenchmark.CMAC_AES_CBC                       thrpt    5  1025615.043 ±  3639.397  ops/s
    MACBenchmark.GMAC_AES_GCM                       thrpt    5   123885.543 ±  1116.567  ops/s
    MACBenchmark.HMAC_SHA512                        thrpt    5   743048.310 ±  5154.154  ops/s
    MACBenchmark.KMAC_128                           thrpt    5   224607.421 ±   857.197  ops/s
    MACBenchmark.KMAC_256                           thrpt    5   228731.416 ±   615.997  ops/s
    RSABenchmark.RSA2048_ENCRYPT_DECRYPT            thrpt    5      994.081 ±     3.415  ops/s
    RSABenchmark.RSA2048_SIGN_VERIFY                thrpt    5      969.879 ±     4.613  ops/s
    RSABenchmark.RSA4096_ENCRYPT_DECRYPT            thrpt    5      150.804 ±     0.721  ops/s
    RSABenchmark.RSA4096_SIGN_VERIFY                thrpt    5      148.749 ±     0.433  ops/s
    SHABenchmark.SHA1                               thrpt    5  4595312.649 ±  9573.851  ops/s
    SHABenchmark.SHA2_256                           thrpt    5  4591422.547 ± 28976.718  ops/s
    SHABenchmark.SHA2_384                           thrpt    5  3659930.424 ± 14330.350  ops/s
    SHABenchmark.SHA2_512                           thrpt    5  3723064.907 ± 26806.463  ops/s
    SHABenchmark.SHA3_256                           thrpt    5  2028268.598 ± 11103.958  ops/s
    SHABenchmark.SHA3_384                           thrpt    5  2006643.004 ± 12672.016  ops/s
    SHABenchmark.SHA3_512                           thrpt    5  2014570.227 ±  6312.249  ops/s
    XORBenchmark.XOR                                thrpt    5   449119.262 ±  7261.436  ops/s

### References

[NIST Cryptographic Algorithm Validation Program](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program)

[OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

[OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

[OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)

[MOZILLA Security/Server Side TLS](https://wiki.mozilla.org/Security/Server_Side_TLS#Recommended_configurations)

---

## OpenSSL

### Cipher + KDF

[openssl enc](https://www.openssl.org/docs/manmaster/man1/openssl-enc.html)

`openssl enc -ciphers`

`openssl enc -in file -out file.bin -cipher -pbkdf2 -iter num -md digest` encrypt, `-d -in file.bin` for decrypt

AES-256-CBC PBKDF2-SHA-256 `openssl enc -in file -out file.bin -aes-256-cbc -pbkdf2 -iter 600000 -md sha256`

`openssl enc -cipher -pbkdf2 -iter num -md digest -P` generate key, iv and salt (hex)

TLS `openssl ciphers`

### KDF

[openssl kdf](https://www.openssl.org/docs/manmaster/man1/openssl-kdf.html)

### Digest

[openssl dgst](https://www.openssl.org/docs/manmaster/man1/openssl-dgst.html)

`openssl dgst -list`

`openssl dgst -digest file`

SHA-256 `openssl dgst -sha256 file`

### Signature

`openssl dgst -digest -sign private.key -out filesignature file` sign file

`openssl dgst -digest -verify public.pem -signature filesignature file` verify signature

`openssl pkeyutl -sign -inkey private.key -in file -out filesignature`
`-rawin` off default hashing pre-sign `-digest name` hash pre-sign, ignore for EdwardCurves(256 bit)

`openssl pkeyutl -verify -pubin -inkey public.pem -in file -sigfile filesignature`

### MAC

[openssl mac](https://www.openssl.org/docs/manmaster/man1/openssl-mac.html)

HMAC-SHA-512 `openssl mac -digest sha512 -macopt hexkey:key -in file hmac` | `openssl dgst -sha512 -hmac key file`

CMAC-AES-128-CBC `openssl mac -cipher aes-128-cbc -macopt hexkey:key -in file cmac`

GMAC-AES-128-GCM `openssl mac -cipher aes-128-gcm -macopt hexkey:key -macopt hexiv:iv -in file gmac`

KMAC-128 `openssl mac -macopt hexkey:key -in file kmac128` `-macopt size:num` `-macopt custom:tag`

### PKCS#8

[openssl pkcs8](https://www.openssl.org/docs/manmaster/man1/openssl-pkcs8.html)

AES-256-CBC PBKDF2-HmacSHA-256
`openssl pkcs8 -topk8 -in private.noenc.key -out private.key -v2 aes-256-cbc -v2prf hmacWithSHA256`

`openssl pkcs8 -traditional -in private.pk8.key -out private.key` to back

### DSA

`openssl dsaparam -out dsaparam.pem 512-10000`

`openssl gendsa -out dsaprivate.noenc.key dsaparam.pem`

`openssl gendsa -out dsaprivate.key -cipher dsaparam.pem` | [openssl pkcs8](#pkcs8)

`openssl dsa -in dsaprivate.key -text -noout`

`openssl dsa -in dsaprivate.key -pubout -out dsapublic.pem`

### ECDSA

`openssl ecparam -list_curves`

`openssl ecparam -name curve -genkey -out ecprivate.noenc.key`

[openssl pkcs8](#pkcs8)

`openssl ec -in ecprivate.key -text -noout`

`openssl ec -in ecprivate.key -pubout -out dsapublic.pem`

### Ed25519, X25519, Ed448, X448

`openssl genpkey -algorithm name -out private.noenc.key`

`openssl genpkey -algorithm name -out private.key -cipher` | [openssl pkcs8](#pkcs8)

`openssl pkey -in private.key -text -noout`

`openssl pkey -in private.key -pubout -out public.pem`

### DH

`openssl dhparam -out dhparam.pem 512-10000`

`openssl genpkey -paramfile dhparam.pem -out dhprivate.noenc.key`

`openssl genkpey -paramfile dhparam.pem -out dhprivate.key -cipher` | [openssl pkcs8](#pkcs8)

`openssl pkey -in dhprivate.key -text -noout`

`openssl pkey -in dhprivate.pem -pubout -out dhpublic.pem`

### RSA

`openssl genrsa -out rsaprivate.noenc.key 512-16384`

`openssl genrsa -out rsaprivate.key -cipher 512-16384` | [openssl pkcs8](#pkcs8)

`openssl rsa -in rsaprivate.key -text -noout`

`openssl rsa -in rsaprivate.key -pubout -out rsapublic.pem`

`openssl pkeyutl -encrypt -pubin -inkey rsapublic.pem -in file -out file.bin` `-certin` cert as a public key

`openssl pkeyutl -decrypt -inkey rsaprivate.key -in file.bin -out file.dec`

### X.509

[openssl req](https://www.openssl.org/docs/manmaster/man1/openssl-req.html)

`openssl req -new -key private.key -out cert.csr -digest -addext "subjectAltName=DNS.1:localhost,DNS.2:osname,IP.1:127.0.0.1,IP.2:192.168.0.100"`

`openssl req -in cert.csr -verify -text -noout`

[OpenSSL x509v3 extensions](https://www.openssl.org/docs/manmaster/man5/x509v3_config.html)

[RedHat x509v3 extensions](https://access.redhat.com/documentation/ru-ru/red_hat_certificate_system/9/html/administration_guide/standard_x.509_v3_certificate_extensions)

    # 2.5.29.19, PKIX Part 1 requires that this extension be marked critical. This extension is evaluated regardless of its criticality
    basicConstraints = critical, CA:TRUE, pathlen:0
    basisConstraints = critical, CA:FALSE

    # 2.5.29.15, This extension may be critical or noncritical. PKIX Part 1 recommends that it should be marked critical if it is used.
    # (SSL Client)digitalSignature, nonRepudiation, (SSL Server)keyEncipherment, dataEncipherment, keyAgreement, (CA Signing)keyCertSign, (CA Signing)cRLSign, encipherOnly, decipherOnly
    keyUsage = critical, keyCertSign, cRLSign
    keyUsage = critical, digitalSignature
    
    # 2.5.29.37, If this extension is marked critical, the certificate must be used for one of the indicated purposes only. If it is not marked critical, it is treated as an advisory field that may be used to identify keys but does not restrict the use of the certificate to the indicated purposes. The Key Usage, Extended Key Usage, and Basic Constraints extensions act together to define the purposes for which the certificate is intended to be used. Applications can use these extensions to disallow the use of a certificate in inappropriate contexts.
    # serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, OCSPSigning, ipsecIKE, msCodeInd, msCodeCom, msCTLSign, msEFS
    extendedKeyUsage = serverAuth, clientAuth
    
    # 2.5.29.14, This extension is always noncritical. PKIX Part 1 requires this extension for all CA certificates and recommends it for all other certificates.
    subjectKeyIdentifier = hash

    # 2.5.29.35, This extension is always noncritical and is always evaluated.
    authorityKeyIdentifier=keyid,issuer:always
    
    # 2.5.29.17, If the certificate's subject field is empty, this extension must be marked critical.
    subjectAltName = DNS:domain, URI:url/uri, IP:ip4/6, email:copy, email:email@, dirName:distinguished name
    
    # 2.5.29.18, PKIX Part 1 recommends that this extension be marked noncritical.
    issuerAltName = issuer:copy

    # 1.3.6.1.5.5.7.1.1, This extension must be noncritical.
    authorityInfoAccess = OCSP;URI:http://ocsp.example.com/,caIssuers;URI:http://myca.example.com/ca.cer
    
    # 2.5.29.31, PKIX recommends that this extension be marked noncritical and that it be supported for all certificates.
    crlDistributionPoints = URI:http://example.com/myca.crl
    
    # 2.5.29.32, This extension may be critical or noncritical. 2.23.140.1.2.1 is EV(Extended Validation)
    certificatePolicies = 2.23.140.1.2.1, ...
   
    # OID definition for use of non-standard extensions, This extension may be critical or noncritical.
    OID = ASN1:UTF8String:value

[openssl x509](https://www.openssl.org/docs/manmaster/man1/openssl-x509.html)

`openssl x509 -req -in cacert.csr -key caprivate.key -out cacert.crt -days 1095 -digest -copy_extensions copy -extfile openssl/x509ext.cnf -extensions ext_v3_ca`
create self-signed CA cert, `-extfile` overrides `-copy_extensions copy` and `-copy_extensions copyall`

`openssl x509 -req -in cert.csr -CAkey caprivate.key -CA=cacert.crt -out cert.crt -days 90 -digest -copy_extensions copy -extfile openssl/x509ext.cnf -extensions ext_v3`
sign cert

`openssl x509 -in cert.crt -text -noout` read details

[openssl ca, crl](https://www.openssl.org/docs/manmaster/man1/openssl-ca.html)

`openssl ca -in cert.csr -out cert.crt -days 90 -config openssl/x509ca.cnf -create_serial -notext -extensions ext_v3`
preconfigured, `-extensions ext_v3_ca` for sign CA

**Configuration required files:**

| Name          | Description                | Default                | Overrides   |
|---------------|----------------------------|------------------------|-------------|
| dir           | Root catalog               | /etc/pki/CA            | openssl/ca  |
| new_certs_dir | New signed certs catalog   | $dir/certs             | $dir/certs  |
| certificate   | CA certificate             | $dir/cacert.pem        | $dir/ca.crt |
| private_key   | CA private key             | $dir/private/cakey.pem | $dir/ca.key |
| serial        | CA serial number from file | $dir/serial            | $dir/serial |
| database      | CA database                | $dir/index.txt         | $dir/index  |

[RedHat CRL v2 extensions](https://access.redhat.com/documentation/ru-ru/red_hat_certificate_system/9/html/administration_guide/crl_extensions)

`openssl ca -gencrl -config openssl/x509ca.cnf -out ca.crl -crl_days 10` based on database

`openssl crl -in ca.crl -inform PEM -out ca.crl.der -outform DER` to binary file

`openssl crl -in ca.crl -text -noout` read details, `-inform DER` for .der

`openssl ca -revoke cert.crt -crl_reason reason -config openssl/x509ca.cnf` ℹ️ after revoke re-gen crl

**CRL Reasons:**

- unspecified
- keyCompromise
- CACompromise
- affiliationChanged
- superseded
- cessationOfOperation
- certificateHold
- removeFromCRL

`openssl ca -status serialNumber -config openssl/x509ca.cnf` check cert status

`openssl ca -valid cert.crt -config openssl/x509ca.cnf` add cert to crl as valid

`openssl ca -updatedb -config openssl/x509ca.cnf` clear expired certs

### PKCS#12

[openssl pkcs12](https://www.openssl.org/docs/manmaster/man1/openssl-pkcs12.html)

`cat target.key target.crt ca.crt > fullchainandkey.pem`

`openssl pkcs12 -export -in fullchainandkey.pem -name name -out name.keystore.p12` export cert chain and key

`openssl pkcs12 -export -in cert.pem -name name -out name.keystore.p12 -nokeys` export only cert or cert chain

`keytool -importkeystore -srckeystore name.keystore.p12 -destkeystore keystore.p12` import all, `-alias name` import one

`keytool -list -keystore keystore.p12` read entries, `-alias name` read entry, `-v` details

`openssl pkcs12 -in keystore.p12`
`-nokeys` certs only `-cacerts` CA certs only, `-clcerts` client certs only, `-nocerts` keys only

`openssl pkcs12 -in keystore.p12 -info -noout` keystore cryptography algorithms info

### DH, ECDH

`openssl pkeyutl -derive -inkey dhprivateA.key -peerkey dhpublicB.key -out secretA.bin`

`openssl pkeyutl -derive -inkey dhprivateB.key -peerkey dhpublicA.key -out secretB.bin`

`openssl dgst -sha256 secretA.bin && openssl dgst -sha256 secretB.bin` hashes must be equals

