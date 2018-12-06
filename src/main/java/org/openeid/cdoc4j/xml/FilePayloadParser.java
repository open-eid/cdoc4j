package org.openeid.cdoc4j.xml;

import org.openeid.cdoc4j.CDOCFileSystemHandler;
import org.openeid.cdoc4j.DataFile;
import org.openeid.cdoc4j.DefaultCDOCFileSystemHandler;
import org.openeid.cdoc4j.EncryptionMethod;
import org.openeid.cdoc4j.exception.CDOCException;
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
    public List<DataFile> parseAndDecryptDDOC(XmlEncParser xmlParser, EncryptionMethod encryptionMethod, SecretKey key) throws XmlParseException {
        DDOCParser ddocParser = new FileDDOCParser(destinationDirectory, cdocFileSystemHandler);
        return xmlParser.parseAndDecryptDDOCPayload(encryptionMethod, key, ddocParser);
    }

    @Override
    public List<DataFile> parseAndDecryptPayload(XmlEncParser xmlParser, EncryptionMethod encryptionMethod, SecretKey key) throws CDOCException {
        return Collections.singletonList(parseAndDecryptPayloadToFile(xmlParser, encryptionMethod, key));
    }

    private DataFile parseAndDecryptPayloadToFile(XmlEncParser xmlParser, EncryptionMethod encryptionMethod, SecretKey key) throws CDOCException {
        String uuidFileName = UUID.randomUUID().toString() + ".cdoc.decrypt.tmp";
        File tempFile = new File(destinationDirectory.getPath(), uuidFileName);
        try (FileOutputStream output = new FileOutputStream(tempFile)) {
            xmlParser.parseAndDecryptEncryptedDataPayload(output, encryptionMethod, key);
            String destinationFileName = xmlParser.getOriginalFileName();
            output.close();
            File destinationFile = new File(destinationDirectory.getPath(), destinationFileName);

            if (destinationFile.exists()) {
                if (cdocFileSystemHandler == null) {
                    cdocFileSystemHandler = new DefaultCDOCFileSystemHandler();
                }
                LOGGER.warn("File {} already exists. Using {}", destinationFile.getAbsolutePath(), cdocFileSystemHandler.getClass().getName());
                destinationFile = cdocFileSystemHandler.onFileExists(destinationFile);
            }
            tempFile.renameTo(destinationFile);
            tempFile.delete();
            return new DataFile(destinationFile);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to construct file output stream", e);
        }
    }
}
