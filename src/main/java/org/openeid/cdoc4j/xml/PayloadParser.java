package org.openeid.cdoc4j.xml;

import org.openeid.cdoc4j.DataFile;
import org.openeid.cdoc4j.EncryptionMethod;
import org.openeid.cdoc4j.exception.CDOCException;
import org.openeid.cdoc4j.xml.XmlEncParser;
import org.openeid.cdoc4j.xml.exception.XmlParseException;

import javax.crypto.SecretKey;

import java.util.List;

public interface PayloadParser {

    List<DataFile> parseAndDecryptDDOC(XmlEncParser xmlParser, EncryptionMethod encryptionMethod, SecretKey key) throws XmlParseException;

    List<DataFile> parseAndDecryptPayload(XmlEncParser xmlParser, EncryptionMethod encryptionMethod, SecretKey key) throws CDOCException;
}
