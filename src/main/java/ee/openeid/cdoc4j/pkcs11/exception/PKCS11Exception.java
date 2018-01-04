package ee.openeid.cdoc4j.pkcs11.exception;

import ee.openeid.cdoc4j.exception.CDOCException;

public class PKCS11Exception extends CDOCException {

    public PKCS11Exception(String message, Exception e) {
        super(message, e);
    }

    public PKCS11Exception(String message) {
        super(message);
    }

}
