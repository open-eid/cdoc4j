package org.cdoc4j;

import org.cdoc4j.crypto.KeyGenUtil;
import org.cdoc4j.exception.CDOCException;
import org.cdoc4j.xml.XmlEnc11Composer;

import javax.crypto.SecretKey;

public class CDOC11Builder extends CDOCBuilder {

    @Override
    public byte[] build() throws CDOCException {
        validateParameters();

        SecretKey key = KeyGenUtil.generateDataEncrytionKey(32);
        return new XmlEnc11Composer().constructXML(EncryptionMethod.AES_256_GCM.getURI(), key, recipients, dataFiles);
    }

}
