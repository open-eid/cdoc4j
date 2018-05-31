package org.openeid.cdoc4j.token.pkcs12.exception;

import org.openeid.cdoc4j.exception.CDOCException;

public class PKCS12Exception extends CDOCException {

    public PKCS12Exception(String message, Exception e) {
        super(message, e);
    }

}
