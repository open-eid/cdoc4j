package org.openeid.cdoc4j.xml;

import com.ctc.wstx.stax.WstxInputFactory;

import org.openeid.cdoc4j.DataFile;
import org.openeid.cdoc4j.xml.exception.XmlParseException;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public abstract class DDOCParser {

    private XMLStreamReader xmlReader;

    public List<DataFile> parseDataFiles(InputStream inputStream) throws XmlParseException, XMLStreamException {
        XMLInputFactory xmlInputFactory = WstxInputFactory.newInstance();
        xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false); // This disables DTDs entirely for that factory
        xmlInputFactory.setProperty("javax.xml.stream.isSupportingExternalEntities", false); // disable external entities
        xmlReader = xmlInputFactory.createXMLStreamReader(inputStream);
        XmlEncParserUtil.goToElement(xmlReader, "SignedDoc");
        List<DataFile> dataFiles = new ArrayList<>();
        try {
            while (XmlEncParserUtil.nextElementIs(xmlReader, "DataFile")) {
                String fileName = XmlEncParserUtil.getAttributeValue(xmlReader, "Filename");
                dataFiles.add(parseDataFile(fileName, xmlReader));
            }
        } catch (Exception e) {
            handleException(e, dataFiles);
            throw e;
        }
        return dataFiles;
    }

    public void close() throws XMLStreamException {
        xmlReader.close();
    }

    abstract DataFile parseDataFile(String fileName, XMLStreamReader xmlReader) throws XMLStreamException, XmlParseException;

    abstract void handleException(Exception e, List<DataFile> dataFiles);

}
