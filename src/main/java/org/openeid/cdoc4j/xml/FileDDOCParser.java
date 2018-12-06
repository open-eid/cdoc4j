package org.openeid.cdoc4j.xml;

import org.openeid.cdoc4j.CDOCFileSystemHandler;
import org.openeid.cdoc4j.DataFile;
import org.openeid.cdoc4j.DefaultCDOCFileSystemHandler;
import org.openeid.cdoc4j.stream.CustomOutputStreamWriter;
import org.openeid.cdoc4j.stream.base64.Base64OutputStream;
import org.openeid.cdoc4j.xml.exception.XmlParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;

public class FileDDOCParser extends DDOCParser {

    private static final Logger LOGGER = LoggerFactory.getLogger(FileDDOCParser.class);

    private File fileDestinationDirectory;
    private CDOCFileSystemHandler cdocFileSystemHandler;

    public FileDDOCParser(File fileDestinationDirectory, CDOCFileSystemHandler cdocFileSystemHandler) {
        this.fileDestinationDirectory = fileDestinationDirectory;
        this.cdocFileSystemHandler = cdocFileSystemHandler;
    }

    @Override
    DataFile parseDataFile(String fileName, XMLStreamReader xmlReader) throws XMLStreamException, XmlParseException {
        try {
            return new DataFile(parseDataFileAndSave(fileName, xmlReader));
        } catch (IOException e) {
            String errorMessage = "Failed to parse DDOC data file named " + fileName;
            LOGGER.error(errorMessage, e);
            throw new XmlParseException(errorMessage, e);
        }
    }

    @Override
    void handleException(Exception e, List<DataFile> dataFiles) {
        LOGGER.error(e.getMessage());
        deleteDataFiles(dataFiles);
    }

    private void deleteDataFiles(List<DataFile> dataFiles) {
        for (DataFile dataFile : dataFiles) {
            File file = new File(fileDestinationDirectory + "/" + dataFile.getName());
            if (file.exists()) {
                LOGGER.warn("Deleting data file: {}", file);
                file.delete();
            }
        }
    }

    private File parseDataFileAndSave(String fileName, XMLStreamReader xmlReader) throws XMLStreamException, IOException {
        String filePath = fileDestinationDirectory.getPath() + "/" + fileName;
        File file = new File(filePath);
        if (file.exists()) {
            LOGGER.warn("File {} already exists. Using CDOCFileSystemHandler", file.getAbsolutePath());
            if (cdocFileSystemHandler == null) {
                cdocFileSystemHandler = new DefaultCDOCFileSystemHandler();
            }
            file = cdocFileSystemHandler.onFileExists(file);
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
}
