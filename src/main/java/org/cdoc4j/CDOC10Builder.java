package org.cdoc4j;

import org.cdoc4j.crypto.KeyGenUtil;
import org.cdoc4j.exception.CDOCException;
import org.cdoc4j.exception.RecipientCertificateException;
import org.cdoc4j.xml.XmlEncComposer;

import javax.crypto.SecretKey;
import java.security.cert.X509Certificate;

public class CDOC10Builder extends CDOCBuilder {

    @Override
    public byte[] build() throws CDOCException {
        validateParameters();

        SecretKey key = KeyGenUtil.generateDataEncrytionKey(16);
        return new XmlEncComposer().constructXML(EncryptionMethod.AES_128_CBC.getURI(), key, recipients, dataFiles);
    }

    @Override
    public CDOCBuilder withRecipient(X509Certificate certificate) throws RecipientCertificateException {
        if (!"RSA".equals(certificate.getPublicKey().getAlgorithm())) {
            throw new RecipientCertificateException("CDOC 1.0 only supports RSA keys!");
        }
        super.withRecipient(certificate);
        return this;
    }

} 
