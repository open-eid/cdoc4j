package org.openeid.cdoc4j.exception;

public class CDOCException extends Exception {

    public CDOCException(String message) {
        super(message);
    }

    public CDOCException(String message, Exception exception) {
        super(message, exception);
    }

} 
