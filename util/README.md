# cdoc4j-util
Command line utility program which uses [cdoc4j](https://github.com/open-eid/cdoc4j) internally.

## Features
* Creation of CDOC documents containing encrypted files
* Decryption of files from CDOC documents

## Supported formats
* **CDOC 1.0** - AES-128-CBC, only RSA recipients (deprecated)
* **CDOC 1.1** - AES-256-GCM, RSA and EC recipients **(Recommended)**

## Requirements
* Java 1.7 
* [Unlimited Strength Jurisdiction Policy](https://github.com/open-eid/cdoc4j/wiki/Enabling-Unlimited-Strength-Jurisdiction-Policy)

## How to use it

* To display usage help
```bash
java -jar cdoc4j-util-0.0.8-SNAPSHOT-jar-with-dependencies.jar
```

* Example of encrypting file to a recipient
```bash
java -jar cdoc4j-util-0.0.8-SNAPSHOT-jar-with-dependencies.jar encrypt -f path/to/desired/file/to/be/encrypted -r path/to/recipent/certificate -o /path/to/output/directory
```

* Example of encrypting multiple files to multiple recipients
```bash
java -jar cdoc4j-util-0.0.8-SNAPSHOT-jar-with-dependencies.jar encrypt -f path/to/file path/to/another/file -r path/to/recipent/certificate path/to/another/recipent/certificate -o /path/to/output/directory
```

* Example of decrypting a file (for soft certificates)
```bash
java -jar cdoc4j-util-0.0.8-SNAPSHOT-jar-with-dependencies.jar decrypt -c /path/to/certificate -k /path/to/private/key -r path/to/recipent/certificate -f path/to/cdoc -o /path/to/output/directory/of/decrypted/file
```

>**Note** Providing the certificate when decrypting is only required when cdoc contains multiple recipients

* Example of decrypting a file (with PKCS#11)
```bash
java -jar cdoc4j-util-0.0.8-SNAPSHOT-jar-with-dependencies.jar pkcs11-decrypt -d /path/to/pkcs11/driver -f /path/to/cdoc -p [pin number] -s [slot] -o /path/to/output/directory/of/decrypted/file
```
