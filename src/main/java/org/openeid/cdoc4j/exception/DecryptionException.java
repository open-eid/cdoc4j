package org.openeid.cdoc4j.exception;

public class DecryptionException extends CDOCException {

    public DecryptionException(String message, Exception e) {
        super(message, e);
    }

    public DecryptionException(String message) {
        super(message);
    }

} 
