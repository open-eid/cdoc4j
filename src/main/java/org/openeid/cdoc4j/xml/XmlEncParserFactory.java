package org.openeid.cdoc4j.xml;

import org.openeid.cdoc4j.EncryptionMethod;
import org.openeid.cdoc4j.exception.CDOCException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.stream.XMLStreamReader;

public class XmlEncParserFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(XmlEncParserFactory.class);

    public static XmlEncParser getXmlEncParser(EncryptionMethod encryptionMethod, XMLStreamReader xmlReader) throws CDOCException {
        switch (encryptionMethod) {
            case AES_128_CBC:
                return new XmlEncParser(xmlReader);
            case AES_256_GCM:
                return new XmlEnc11Parser(xmlReader);
            default:
                String message = "Error initializing CDOC parser: unknown encryption method algorithm!";
                LOGGER.error(message);
                throw new CDOCException(message);
        }
    }
} 
