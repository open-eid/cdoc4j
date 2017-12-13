package org.cdoc4j.xml;

import org.cdoc4j.exception.CDOCException;
import org.cdoc4j.xml.exception.XmlParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.InputStream;

public class XMLDocumentBuilder {

    private static final Logger LOGGER = LoggerFactory.getLogger(XmlEncParser.class);

    public static Document createDocument() throws CDOCException {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder docBuilder = factory.newDocumentBuilder();
            Document document = docBuilder.newDocument();
            document.setXmlStandalone(true);
            return document;
        } catch (ParserConfigurationException e) {
            String message = "Error building XML document!";
            LOGGER.error(message, e);
            throw new CDOCException(message, e);
        }
    }

    public static Document buildDocument(InputStream inputStream) throws XmlParseException {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

            // Disable XML External Entity injection
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

            DocumentBuilder dBuilder = factory.newDocumentBuilder();
            return dBuilder.parse(inputStream);
        } catch (Exception e) {
            String message = "Error building XML document from input stream!";
            LOGGER.error(message, e);
            throw new XmlParseException(message, e);
        }
    }

} 
