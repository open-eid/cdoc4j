package org.openeid.cdoc4j.xml.exception;

import org.openeid.cdoc4j.exception.CDOCException;

public class XmlParseException extends CDOCException {

    public XmlParseException(String message, Exception exception) {
        super(message, exception);
    }

    public XmlParseException(String message) {
        super(message);
    }

} 
