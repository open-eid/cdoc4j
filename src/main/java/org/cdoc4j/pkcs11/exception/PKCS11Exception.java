package org.cdoc4j.pkcs11.exception;

import org.cdoc4j.exception.CDOCException;

public class PKCS11Exception extends CDOCException {

    public PKCS11Exception(String message, Exception e) {
        super(message, e);
    }

    public PKCS11Exception(String message) {
        super(message);
    }

}