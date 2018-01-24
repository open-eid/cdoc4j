package org.openeid.cdoc4j.xml;

import org.openeid.cdoc4j.EncryptionMethod;
import org.openeid.cdoc4j.exception.CDOCException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

public class XmlEncParserFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(XmlEncParserFactory.class);


    public static XmlEncParser getXmlEncParser(Document document) throws CDOCException {
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expression = xpath.compile("/EncryptedData/EncryptionMethod");
            Node encryptionMethod = (Node) expression.evaluate(document, XPathConstants.NODE);
            String encrytionMethodUri = encryptionMethod.getAttributes().getNamedItem("Algorithm").getTextContent();
            if (EncryptionMethod.AES_128_CBC.getURI().equals(encrytionMethodUri)) {
                return new XmlEncParser(document);
            } else if (EncryptionMethod.AES_256_GCM.getURI().equals(encrytionMethodUri)) {
                return new XmlEnc11Parser(document);
            } else {
                String message = "Error initializing CDOC parser: unknown encryption method algorithm!";
                LOGGER.error(message);
                throw new CDOCException(message);
            }
        } catch (XPathExpressionException e) {
            String message = "Error initializing CDOC parser from XML!";
            LOGGER.error(message, e);
            throw new CDOCException(message, e);
        }
    }

} 
