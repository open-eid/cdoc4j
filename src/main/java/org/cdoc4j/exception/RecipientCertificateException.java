package org.cdoc4j.exception;

public class RecipientCertificateException extends CDOCException {

    public RecipientCertificateException(String message, Exception e) {
        super(message, e);
    }

    public RecipientCertificateException(String message) {
        super(message);
    }

}
