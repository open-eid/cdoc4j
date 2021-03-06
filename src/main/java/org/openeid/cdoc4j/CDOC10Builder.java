package org.openeid.cdoc4j;

import org.apache.commons.io.IOUtils;
import org.openeid.cdoc4j.crypto.KeyGenUtil;
import org.openeid.cdoc4j.exception.CDOCException;
import org.openeid.cdoc4j.exception.RecipientCertificateException;
import org.openeid.cdoc4j.xml.XmlEncComposer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.security.cert.X509Certificate;

/**
 * Class for building CDOC 1.0 documents
 * <p>
 * @deprecated use {@link CDOC11Builder} instead
 * <p>
 * Required parameters:
 * <ul>
 * <li><b>{@link DataFile}</b> - the file to be encrypted (at least one is mandatory, also supports multiple files)</li>
 * <li><b>{@link X509Certificate}</b> - recipient a.k.a. receiver (mandatory, also supports multiple recipients)</li>
 * </ul>
 */
@Deprecated
public class CDOC10Builder extends CDOCBuilder {

    private static final Logger LOGGER = LoggerFactory.getLogger(CDOC10Builder.class);

    @Override
    public void build() throws CDOCException {
        try {
            validateParameters();

            SecretKey key = KeyGenUtil.generateDataEncryptionKey(16);
            LOGGER.info("Start composing CDOC");
            new XmlEncComposer().constructXML(EncryptionMethod.AES_128_CBC, key, recipients, dataFiles, output);

            LOGGER.info("CDOC composed successfully!");
        } finally {
            IOUtils.closeQuietly(this.output);
            for (DataFile dataFile : dataFiles) {
                IOUtils.closeQuietly(dataFile.getContent());
            }
        }
    }

    @Override
    public CDOCBuilder withRecipient(X509Certificate certificate) throws RecipientCertificateException {
        if (!"RSA".equals(certificate.getPublicKey().getAlgorithm())) {
            String message = "CDOC 1.0 only supports RSA keys!";
            LOGGER.error(message);
            throw new RecipientCertificateException(message);
        }
        super.withRecipient(certificate);
        return this;
    }

} 
