package org.cdoc4j;

import org.cdoc4j.exception.CDOCException;
import org.cdoc4j.exception.DataFileMissingException;
import org.cdoc4j.exception.RecipientCertificateException;
import org.cdoc4j.exception.RecipientMissingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public abstract class CDOCBuilder {

    private static final Logger LOGGER = LoggerFactory.getLogger(CDOCBuilder.class);

    private static final String V1_0 = "1.0";
    private static final String V1_1 = "1.1";

    protected List<X509Certificate> recipients = new ArrayList<>();
    protected List<DataFile> dataFiles = new ArrayList<>();

    public static CDOCBuilder version(String version) throws CDOCException {
        switch (version) {
            case V1_0:
                return new CDOC10Builder();
            case V1_1:
                return new CDOC11Builder();
        }
        throw new CDOCException("Invalid version: " + version);
    }

    public static CDOCBuilder defaultVersion() throws CDOCException {
        return version(V1_1);
    }

    public CDOCBuilder withDataFile(DataFile dataFile) {
        dataFiles.add(dataFile);
        return this;
    }

    public CDOCBuilder withDataFile(Path path) throws IOException {
        byte[] data = Files.readAllBytes(path);
        DataFile dataFile = new DataFile(path.getFileName().toString(), data);
        return withDataFile(dataFile);
    }

    public CDOCBuilder withDataFile(File file) throws IOException {
        Path path = file.toPath();
        return withDataFile(path);
    }

    public CDOCBuilder withRecipient(X509Certificate certificate) throws RecipientCertificateException {
        validateRecipientCertificate(certificate);
        recipients.add(certificate);
        return this;
    }

    public CDOCBuilder withRecipient(InputStream inputStream) throws RecipientCertificateException {
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(inputStream);
            return withRecipient(certificate);
        } catch (CertificateException e) {
            String message = "Error reading certificate from input stream!";
            LOGGER.error(message, e);
            throw new RecipientCertificateException(message, e);
        }
    }

    public void buildToOutputStream(OutputStream outputStream) throws Exception {
        byte[] cdocBytes = build();
        outputStream.write(cdocBytes);
        outputStream.close();
    }

    public abstract byte[] build() throws CDOCException;

    protected void validateParameters() throws CDOCException {
        if (dataFiles == null || dataFiles.isEmpty()) {
            String message = "CDOC Must contain at least 1 data file!";
            LOGGER.error(message);
            throw new DataFileMissingException(message);
        }
        if (recipients == null || recipients.isEmpty()) {
            String message = "CDOC Must contain at least 1 recipient!";
            LOGGER.error(message);
            throw new RecipientMissingException(message);
        }
    }

    private void validateRecipientCertificate(X509Certificate certificate) throws RecipientCertificateException {
        boolean[] keyUsage = certificate.getKeyUsage();
        if ("RSA".equals(certificate.getPublicKey().getAlgorithm()) && !keyUsage[2]) {
            String message = "Recipient's certificate doesn't contain 'keyEncipherment' key usage!";
            LOGGER.error(message);
            throw new RecipientCertificateException(message);
        } else if (certificate.getPublicKey().getAlgorithm().startsWith("EC") && !keyUsage[4]) {
            String message = "Recipient's certificate doesn't contain 'keyAgreement' key usage!";
            LOGGER.error(message);
            throw new RecipientCertificateException(message);
        }


    }

}
