# cdoc4j-util
Command line utility program which uses [cdoc4j](https://github.com/open-eid/cdoc4j) internally.

## Features
* Creation of CDOC documents containing encrypted files
* Decryption of files from CDOC documents

## Supported formats
* **CDOC 1.0** - AES-128-CBC, only RSA recipients (deprecated)
* **CDOC 1.1** - AES-256-GCM, RSA and EC recipients **(Recommended)**

## Requirements
* Java 1.8
* [Unlimited Strength Jurisdiction Policy](https://github.com/open-eid/cdoc4j/wiki/Enabling-Unlimited-Strength-Jurisdiction-Policy)

## How to use it

* To display usage help
```bash
java -jar cdoc4j-util-1.3.jar
```

* Example of encrypting file to a recipient
```bash
java -jar cdoc4j-util-1.3.jar encrypt -f path/to/desired/file/to/be/encrypted -r path/to/recipent/certificate -o /path/to/output/directory
```

* Example of encrypting multiple files to multiple recipients
```bash
java -jar cdoc4j-util-1.3.jar encrypt -f path/to/file path/to/another/file -r path/to/recipent/certificate path/to/another/recipent/certificate -o /path/to/output/directory
```

* Example of decrypting a file with PKCS#11
```bash
java -jar cdoc4j-util-1.3.jar pkcs11-decrypt -f /path/to/cdoc -d /path/to/pkcs11/driver -p [pin number] -s [slot] -o /path/to/output/directory/of/decrypted/file
```

* Example of decrypting a file with PKCS#12
```bash
java -jar cdoc4j-util-1.3.jar pkcs12-decrypt -f path/to/cdoc -k /path/to/p12/keystore -p [keystore password] -o /path/to/output/directory/of/decrypted/file
```
