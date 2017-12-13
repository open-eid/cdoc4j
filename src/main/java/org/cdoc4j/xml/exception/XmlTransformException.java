package org.cdoc4j.xml.exception;

import org.cdoc4j.exception.CDOCException;

public class XmlTransformException extends CDOCException {

    public XmlTransformException(String message, Exception exception) {
        super(message, exception);
    }

} 
