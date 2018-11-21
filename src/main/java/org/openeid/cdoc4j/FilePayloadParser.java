package org.openeid.cdoc4j;

import org.openeid.cdoc4j.exception.CDOCException;
import org.openeid.cdoc4j.xml.DDOCParser;
import org.openeid.cdoc4j.xml.FileDDOCParser;
import org.openeid.cdoc4j.xml.XmlEncParser;
import org.openeid.cdoc4j.xml.exception.XmlParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

public class FilePayloadParser implements PayloadParser {

    private static final Logger LOGGER = LoggerFactory.getLogger(FilePayloadParser.class);

    private final File destinationDirectory;
    private CDOCFileSystemHandler cdocFileSystemHandler;

    public FilePayloadParser(File destinationDirectory, CDOCFileSystemHandler cdocFileSystemHandler) {
        this.destinationDirectory = destinationDirectory;
        this.cdocFileSystemHandler = cdocFileSystemHandler;
    }

    @Override
    public List<DataFile> parseDDOC(XmlEncParser xmlParser, EncryptionMethod encryptionMethod, SecretKey key) throws XmlParseException {
        DDOCParser ddocParser = new FileDDOCParser(destinationDirectory, cdocFileSystemHandler);
        return xmlParser.parseAndDecryptDDOCPayload(encryptionMethod, key, ddocParser);
    }

    @Override
    public List<DataFile> parsePayload(XmlEncParser xmlParser, EncryptionMethod encryptionMethod, SecretKey key) throws CDOCException {
        return Collections.singletonList(parseAndDecryptPayloadToFile(xmlParser, encryptionMethod, key));
    }

    private DataFile parseAndDecryptPayloadToFile(XmlEncParser xmlParser, EncryptionMethod encryptionMethod, SecretKey key) throws CDOCException {
        String uuidFileName = UUID.randomUUID().toString() + ".cdoc.decrypt.tmp";
        File file = new File(destinationDirectory.getPath(), uuidFileName);
        try (FileOutputStream output = new FileOutputStream(file)) {
            xmlParser.parseAndDecryptEncryptedDataPayload(output, encryptionMethod, key);
            String originalFileName = xmlParser.getOriginalFileName();
            output.close();
            File originalFile = new File(destinationDirectory.getPath(), originalFileName);

            if (originalFile.exists()) {
                if (cdocFileSystemHandler == null) {
                    cdocFileSystemHandler = new DefaultCDOCFileSystemHandler();
                }
                LOGGER.warn("File {} already exists. Using {}", originalFile, cdocFileSystemHandler.getClass().getName());
                originalFile = cdocFileSystemHandler.onFileExists(originalFile);
            }
            file.renameTo(originalFile);
            file.delete();
            return new DataFile(originalFile);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to construct file output stream", e);
        }
    }
}
