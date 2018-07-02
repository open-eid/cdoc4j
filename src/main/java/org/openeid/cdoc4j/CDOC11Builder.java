package org.openeid.cdoc4j;

import org.apache.commons.io.IOUtils;
import org.openeid.cdoc4j.crypto.KeyGenUtil;
import org.openeid.cdoc4j.exception.CDOCException;
import org.openeid.cdoc4j.xml.XmlEnc11Composer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.security.cert.X509Certificate;

/**
 * Class for building CDOC 1.1 documents
 * <p>
 * Required parameters:
 * <ul>
 * <li><b>{@link DataFile}</b> - the file to be encrypted (at least one is mandatory, also supports multiple files)</li>
 * <li><b>{@link X509Certificate}</b> - recipient a.k.a. receiver (mandatory, also supports multiple recipients)</li>
 * </ul>
 */
public class CDOC11Builder extends CDOCBuilder {

    private static final Logger LOGGER = LoggerFactory.getLogger(CDOC11Builder.class);

    @Override
    public void build() throws CDOCException {
        try {
            validateParameters();

            SecretKey key = KeyGenUtil.generateDataEncryptionKey(32);
            LOGGER.info("Start composing CDOC");
            new XmlEnc11Composer().constructXML(EncryptionMethod.AES_256_GCM, key, recipients, dataFiles, output);
            LOGGER.info("CDOC composed successfully!");
        } finally {
            IOUtils.closeQuietly(this.output);
            for (DataFile dataFile : dataFiles) {
                IOUtils.closeQuietly(dataFile.getContent());
            }
        }
    }
}
