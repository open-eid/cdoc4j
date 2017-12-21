package org.cdoc4j;

import org.cdoc4j.crypto.KeyGenUtil;
import org.cdoc4j.exception.CDOCException;
import org.cdoc4j.xml.XmlEnc11Composer;
import org.cdoc4j.xml.XmlEncComposer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;

public class CDOC11Builder extends CDOCBuilder {

    private static final Logger LOGGER = LoggerFactory.getLogger(CDOC11Builder.class);

    @Override
    public byte[] build() throws CDOCException {
        validateParameters();

        SecretKey key = KeyGenUtil.generateDataEncrytionKey(32);
        LOGGER.info("Start composing CDOC");
        byte[] cdocBytes = new XmlEnc11Composer().constructXML(EncryptionMethod.AES_256_GCM.getURI(), key, recipients, dataFiles);
        LOGGER.info("CDOC composed successfully!");
        return cdocBytes;
    }

}
