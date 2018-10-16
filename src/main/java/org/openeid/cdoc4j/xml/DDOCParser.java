package org.openeid.cdoc4j.xml;

import com.ctc.wstx.stax.WstxInputFactory;

import org.openeid.cdoc4j.CDOCFileSystemHandler;
import org.openeid.cdoc4j.DefaultCDOCFileSystemHandler;
import org.openeid.cdoc4j.stream.CustomOutputStreamWriter;
import org.openeid.cdoc4j.stream.base64.Base64OutputStream;
import org.openeid.cdoc4j.xml.exception.XmlParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class DDOCParser {

    private static final Logger LOGGER = LoggerFactory.getLogger(DDOCParser.class);

    private final XMLStreamReader xmlReader;
    private final File fileDestinationDirectory;
    private CDOCFileSystemHandler cdocFileSystemHandler;

    public DDOCParser(InputStream inputStream, File fileDestinationDirectory, CDOCFileSystemHandler cdocFileSystemHandler) throws XMLStreamException {
        XMLInputFactory xmlInputFactory = WstxInputFactory.newInstance();
        xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false); // This disables DTDs entirely for that factory
        xmlInputFactory.setProperty("javax.xml.stream.isSupportingExternalEntities", false); // disable external entities
        this.cdocFileSystemHandler = cdocFileSystemHandler;
        xmlReader = xmlInputFactory.createXMLStreamReader(inputStream);
        this.fileDestinationDirectory = fileDestinationDirectory;
    }

    public List<File> parseDataFiles() throws XmlParseException, XMLStreamException {

        XmlEncParserUtil.goToElement(xmlReader, "SignedDoc");

        List<File> dataFiles = new ArrayList<>();
        while (XmlEncParserUtil.nextElementIs(xmlReader, "DataFile")) {
            dataFiles.add(parseDataFile());
        }

        return dataFiles;
    }

    private File parseDataFile() throws XmlParseException, XMLStreamException {
        String fileName = XmlEncParserUtil.getAttributeValue(xmlReader, "Filename");
        try {
            return parseDataFileAndSaveToFile(fileName);
        } catch (IOException e) {
            String errorMessage = "Failed to parse DDOC data file named " + fileName;
            LOGGER.error(errorMessage, e);
            throw new XmlParseException(errorMessage, e);
        }
    }

    private File parseDataFileAndSaveToFile(String fileName) throws XMLStreamException, IOException {
        String filePath = fileDestinationDirectory.getPath() + "/" + fileName;
        File file = new File(filePath);
        if (file.exists()) {
            LOGGER.warn("File {} already exists. Using CDOCFileSystemHandler", file);
            if (cdocFileSystemHandler == null) {
                cdocFileSystemHandler = new DefaultCDOCFileSystemHandler();
            }
            file = cdocFileSystemHandler.handleExistingFileIssue(file);
        }
        try (FileOutputStream fileDestination = new FileOutputStream(file);
             Base64OutputStream base64DecodeStream = new Base64OutputStream(fileDestination, false);
             CustomOutputStreamWriter outputWriter = new CustomOutputStreamWriter(base64DecodeStream)) {

            XmlEncParserUtil.readCharacters(xmlReader, outputWriter, 1024);
            outputWriter.flush();
            fileDestination.close();
            return file;
        }
    }

    public void close() throws XMLStreamException {
        xmlReader.close();
    }
} 
