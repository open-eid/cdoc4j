package org.openeid.cdoc4j;

import org.openeid.cdoc4j.exception.CDOCException;
import org.openeid.cdoc4j.xml.XmlEncParser;
import org.openeid.cdoc4j.xml.exception.XmlParseException;

import javax.crypto.SecretKey;

import java.util.List;

public interface PayloadParser {

    List<DataFile> parseDDOC(XmlEncParser xmlParser, EncryptionMethod encryptionMethod, SecretKey key) throws XmlParseException;

    List<DataFile> parsePayload(XmlEncParser xmlParser, EncryptionMethod encryptionMethod, SecretKey key) throws CDOCException;
}
