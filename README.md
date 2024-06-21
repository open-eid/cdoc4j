# cdoc4j
Java library for working with CDOC documents.

## Origin
This project started with the help of European Regional Development Fund.

![Euroopa Regionaalarengu Fond](reg_logo.png)

# Build status

![Build status](https://github.com/open-eid/cdoc4j/actions/workflows/cdoc4j-verify.yml/badge.svg?branch=master)

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
Take a look at the [examples](https://github.com/open-eid/cdoc4j/wiki/Examples-of-how-to-use-it)

## Decrypting a file using a smart card with Java version 17 or higher
Using a smart card to decrypt a file while using Java 17 or a later version, an extra JVM argument is required:
```bash
--add-exports jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED
```

## Maven Central
You can use the library as a dependency from [Maven Central](http://mvnrepository.com/artifact/org.open-eid.cdoc4j/cdoc4j)

```xml
<dependency>
    <groupId>org.open-eid.cdoc4j</groupId>
    <artifactId>cdoc4j</artifactId>
    <version>1.5</version>
</dependency>
```
