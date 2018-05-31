package org.openeid.cdoc4j.token.pkcs11.exception;

public class IncorrectPinException extends PKCS11Exception {

    public IncorrectPinException(String message, Exception e) {
        super(message, e);
    }
}
