# Summary

Demo of PKCS7 parsing error using [avs_crypto_parse_pkcs7_certs_only](https://github.com/AVSystem/avs_commons/blob/c2ebe620d16a508e14fabfd9725059e812a8f2eb/include_public/avsystem/commons/avs_crypto_pki.h#L981), when PKCS7 file contains multiple "Undefined length" ASN1 tags.

# Usage

```
$ west build -b native_posix_64 . -p -t run
*** Booting Zephyr OS build zephyr-v3.1.0-2125-gd2b83ebdc597  ***

Decode good.pkcs7.der using anjay

cert. version     : 3
serial number     : xx:xx:xx:xx:xx:xx:xx
issuer name       : CN=xx
subject name      : CN=xx
issued  on        : 2016-01-26 14:06:58
expires on        : 2026-01-26 14:16:58
signed using      : RSA with SHA-256
RSA key size      : 4096 bits
basic constraints : CA=true
key usage         : Digital Signature, Key Cert Sign, CRL Sign


Decode bad.pkcs7.der using anjay

[00:00:00.000,000] <err> anjay: [avs_crypto_pki] Encapsulated content for PKCS#7 certs-only MUST be absent
avs_crypto_parse_pkcs7_certs_only error
```