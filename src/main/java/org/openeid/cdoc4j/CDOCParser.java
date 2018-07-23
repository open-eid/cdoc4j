package org.openeid.cdoc4j;

import com.ctc.wstx.stax.WstxInputFactory;
import org.apache.commons.io.IOUtils;
import org.openeid.cdoc4j.xml.XmlEncParser;
import org.openeid.cdoc4j.xml.XmlEncParserFactory;
import org.openeid.cdoc4j.xml.XmlEncParserUtil;
import org.openeid.cdoc4j.xml.exception.XmlParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class CDOCParser {

    private static final Logger LOGGER = LoggerFactory.getLogger(CDOCParser.class);

    public static List<String> getDataFileNames(InputStream cdocStream) throws XmlParseException {
        XMLStreamReader cdocReader = initialiseXmlReader(cdocStream);
        try {
            XmlEncParserUtil.goToElement(cdocReader, "EncryptionProperties");
            List<String> fileNames = new ArrayList<>();
            while (XmlEncParserUtil.nextElementIs(cdocReader, "EncryptionProperty")) {
                String nameAttributeValue = XmlEncParserUtil.getAttributeValue(cdocReader, "Name");
                if (nameAttributeValue.equals("orig_file")) {
                    String filePropertyValue = XmlEncParserUtil.readCharacters(cdocReader);
                    String[] filePropertyPars = filePropertyValue.split("\\|");
                    fileNames.add(filePropertyPars[0]);
                }
            }
            return fileNames;
        } catch (XMLStreamException e) {
            String message = "Error parsing file names from CDOC";
            LOGGER.error(message, e);
            throw new XmlParseException(message, e);
        } finally {
            try {
                IOUtils.closeQuietly(cdocStream);
                cdocReader.close();
            } catch (XMLStreamException e) {
                throw new IllegalStateException("Failed to close XMLStreamReader", e);
            }
        }
    }

    public static List<Recipient> getRecipients(InputStream cdocStream) throws XmlParseException {
        XMLStreamReader cdocReader = initialiseXmlReader(cdocStream);
        try {
            XmlEncParserUtil.goToElement(cdocReader, "EncryptedData");
            XmlEncParserUtil.goToElement(cdocReader, "EncryptionMethod");
            String encryptionMethodUri = XmlEncParserUtil.getAttributeValue(cdocReader, "Algorithm");
            EncryptionMethod encryptionMethod = EncryptionMethod.fromURI(encryptionMethodUri);
            XmlEncParser xmlParser = XmlEncParserFactory.getXmlEncParser(encryptionMethod, cdocReader);
            return xmlParser.getRecipients();
        } catch (Exception e) {
            throw new XmlParseException("Error parsing recipients from CDOC", e);
        } finally {
            if (cdocReader != null) {
                try {
                    cdocReader.close();
                } catch (XMLStreamException e) {
                    throw new IllegalStateException("Failed to close XMLStreamReader", e);
                }
            }
            IOUtils.closeQuietly(cdocStream);
        }
    }

    private static XMLStreamReader initialiseXmlReader(InputStream cdocStream) throws XmlParseException {
        try {
            XMLInputFactory xmlInputFactory = WstxInputFactory.newInstance();
            xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            xmlInputFactory.setProperty("javax.xml.stream.isSupportingExternalEntities", false);
            return xmlInputFactory.createXMLStreamReader(cdocStream);
        } catch (XMLStreamException e) {
            String message = "Error initiating XML reader";
            LOGGER.error(message, e);
            throw new XmlParseException(message, e);
        }
    }
}
