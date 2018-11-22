package org.openeid.cdoc4j;

import org.openeid.cdoc4j.exception.CDOCException;
import org.openeid.cdoc4j.xml.DDOCParser;
import org.openeid.cdoc4j.xml.MemoryDDOCParser;
import org.openeid.cdoc4j.xml.XmlEncParser;
import org.openeid.cdoc4j.xml.exception.XmlParseException;

import javax.crypto.SecretKey;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;

public class MemoryPayloadParser implements PayloadParser{

    @Override
    public List<DataFile> parseAndDecryptDDOC(XmlEncParser xmlParser, EncryptionMethod encryptionMethod, SecretKey key) throws XmlParseException {
        DDOCParser ddocParser = new MemoryDDOCParser();
        return xmlParser.parseAndDecryptDDOCPayload(encryptionMethod, key, ddocParser);
    }

    @Override
    public List<DataFile> parseAndDecryptPayload(XmlEncParser xmlParser, EncryptionMethod encryptionMethod, SecretKey key) throws CDOCException {
        return Collections.singletonList(parseAndDecryptPayloadToMemory(xmlParser, encryptionMethod, key));
    }

    private DataFile parseAndDecryptPayloadToMemory(XmlEncParser xmlParser, EncryptionMethod encryptionMethod, SecretKey key) throws CDOCException {
        DataFile dataFile;
        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            xmlParser.parseAndDecryptEncryptedDataPayload(byteArrayOutputStream, encryptionMethod, key);
            String originalFileName = xmlParser.getOriginalFileName();
            InputStream inputStream = new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
            byteArrayOutputStream.flush();
            byteArrayOutputStream.close();
            dataFile = new DataFile(originalFileName, inputStream, inputStream.available());
        } catch (IOException e) {
            throw new IllegalStateException("Failed to create data file", e);
        }
        return dataFile;
    }
}
