package org.openeid.cdoc4j.xml;

import org.openeid.cdoc4j.DataFile;
import org.openeid.cdoc4j.stream.CustomOutputStreamWriter;
import org.openeid.cdoc4j.stream.base64.Base64OutputStream;
import org.openeid.cdoc4j.xml.exception.XmlParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

public class MemoryDDOCParser extends DDOCParser {

    private static final Logger LOGGER = LoggerFactory.getLogger(MemoryDDOCParser.class);

    @Override
    DataFile parseDataFile(String fileName, XMLStreamReader xmlReader) throws XmlParseException {
        try {
            InputStream inputStream = parseDataFileAndSave(xmlReader);
            return new DataFile(fileName, inputStream, inputStream.available());
        } catch (IOException | XMLStreamException e) {
            String errorMessage = "Failed to parse DDOC data file named " + fileName;
            LOGGER.error(errorMessage, e);
            throw new XmlParseException(errorMessage, e);
        }
    }

    @Override
    void handleException(Exception e, List<DataFile> dataFiles) {
        LOGGER.error(e.getMessage());
    }

    private InputStream parseDataFileAndSave(XMLStreamReader xmlReader) throws XMLStreamException, IOException {

        try (ByteArrayOutputStream fileDestination = new ByteArrayOutputStream();
             Base64OutputStream base64DecodeStream = new Base64OutputStream(fileDestination, false);
             CustomOutputStreamWriter outputWriter = new CustomOutputStreamWriter(base64DecodeStream)) {

            XmlEncParserUtil.readCharacters(xmlReader, outputWriter, 1024);
            outputWriter.flush();

            InputStream inputStream = new ByteArrayInputStream(fileDestination.toByteArray());
            fileDestination.close();
            return inputStream;
        }
    }
}
