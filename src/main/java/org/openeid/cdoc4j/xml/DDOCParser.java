package org.openeid.cdoc4j.xml;

import org.apache.commons.codec.binary.Base64OutputStream;
import org.openeid.cdoc4j.DataFile;
import org.openeid.cdoc4j.stream.CustomOutputStreamWriter;
import org.openeid.cdoc4j.xml.exception.XmlParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class DDOCParser {

    private static final Logger LOGGER = LoggerFactory.getLogger(DDOCParser.class);

    private final XMLStreamReader xmlReader;
    private final File fileDestinationDirectory;

    public DDOCParser(InputStream inputStream, File fileDestinationDirectory) throws XMLStreamException {
        XMLInputFactory xmlInputFactory = XMLInputFactory.newFactory();
        xmlReader = xmlInputFactory.createXMLStreamReader(inputStream);
        this.fileDestinationDirectory = fileDestinationDirectory;
    }

    public List<DataFile> parseDataFiles() throws XmlParseException, XMLStreamException {

        XmlEncParserUtil.goToElement(xmlReader, "SignedDoc");

        List<DataFile> dataFiles = new ArrayList<>();
        while (XmlEncParserUtil.nextElementIs(xmlReader, "DataFile")) {
            dataFiles.add(parseDataFile());
        }

        return dataFiles;
    }

    private DataFile parseDataFile() throws XmlParseException, XMLStreamException {
        String fileName = XmlEncParserUtil.getAttributeValue(xmlReader, "Filename");
        try {
            if (fileDestinationDirectory == null) {
                return parseDataFileAndSaveToByteArrayStream(fileName);
            } else {
                return parseDataFileAndSaveToFile(fileName);
            }
        } catch (IOException e) {
            String errorMessage = "Failed to parse DDOC data file named " + fileName;
            LOGGER.error(errorMessage, e);
            throw new XmlParseException(errorMessage, e);
        }
    }

    private DataFile parseDataFileAndSaveToByteArrayStream(String fileName) throws XMLStreamException, IOException {
        try (ByteArrayOutputStream output = new ByteArrayOutputStream();
             Base64OutputStream base64DecodeStream = new Base64OutputStream(output, false);
             CustomOutputStreamWriter outputWriter = new CustomOutputStreamWriter(base64DecodeStream)) {

            XmlEncParserUtil.readCharacters(xmlReader, outputWriter, 1024);
            outputWriter.flush();
            return new DataFile(fileName, output.toByteArray());
        }
    }

    private DataFile parseDataFileAndSaveToFile(String fileName) throws XMLStreamException, IOException {
        String filePath = fileDestinationDirectory.getPath() + "/" + fileName;
        try (FileOutputStream fileDestination = new FileOutputStream(filePath);
             Base64OutputStream base64DecodeStream = new Base64OutputStream(fileDestination, false);
             CustomOutputStreamWriter outputWriter = new CustomOutputStreamWriter(base64DecodeStream)) {

            XmlEncParserUtil.readCharacters(xmlReader, outputWriter, 1024);
            outputWriter.flush();
            fileDestination.close();
            return new DataFile(new File(filePath));
        }
    }

    public void close() throws XMLStreamException {
        xmlReader.close();
    }
} 
