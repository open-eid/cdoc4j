package org.cdoc4j;

import org.cdoc4j.crypto.KeyGenUtil;
import org.cdoc4j.exception.CDOCException;
import org.cdoc4j.exception.RecipientCertificateException;
import org.cdoc4j.xml.XmlEncComposer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.security.cert.X509Certificate;

public class CDOC10Builder extends CDOCBuilder {

    private static final Logger LOGGER = LoggerFactory.getLogger(CDOC10Builder.class);

    @Override
    public byte[] build() throws CDOCException {
        validateParameters();

        SecretKey key = KeyGenUtil.generateDataEncrytionKey(16);
        LOGGER.info("Start composing CDOC");
        byte[] cdocBytes = new XmlEncComposer().constructXML(EncryptionMethod.AES_128_CBC.getURI(), key, recipients, dataFiles);
        LOGGER.info("CDOC composed successfully!");
        return cdocBytes;
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
