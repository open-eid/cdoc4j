package org.openeid.cdoc4j;

import org.apache.commons.io.IOUtils;
import org.openeid.cdoc4j.exception.CDOCException;
import org.openeid.cdoc4j.exception.DataFileMissingException;
import org.openeid.cdoc4j.exception.RecipientCertificateException;
import org.openeid.cdoc4j.exception.RecipientMissingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Abstraction class for building CDOC documents
 * <p>
 * Required parameters:
 * <ul>
 * <li><b>{@link DataFile}</b> - the file to be encrypted (at least one is mandatory, also supports multiple files)</li>
 * <li><b>{@link X509Certificate}</b> - recipient a.k.a. receiver (mandatory, also supports multiple recipients)</li>
 * </ul>
 * <p>
 *   <b>Example of encrypting file into CDOC</b>
 * </p>
 * <p><code>
 *   DataFile dataFile = new DataFile(new File("/path/to/file")); <br/>
 *   CDOCBuilder.defaultVersion() <br/>
 *   &nbsp;&nbsp;.withDataFile(dataFile) <br/>
 *   &nbsp;&nbsp;.withRecipient(certificate) <br/>
 *   &nbsp;&nbsp;.buildToFile(new File("/path/to/cdoc")); <br/>
 * </code></p>
 */
public abstract class CDOCBuilder {

    private static final Logger LOGGER = LoggerFactory.getLogger(CDOCBuilder.class);

    private static final String V1_0 = "1.0";
    private static final String V1_1 = "1.1";

    protected List<X509Certificate> recipients = new ArrayList<>();
    protected List<DataFile> dataFiles = new ArrayList<>();
    protected OutputStream output;

    /**
     * Constructs an instance of {@link CDOCBuilder} for the desired version of CDOC
     *
     * @param version of the desired CDOC
     * @throws CDOCException when the version input is invalid
     * @return an instance of {@link CDOCBuilder} for the desired version of CDOC
     */
    public static CDOCBuilder version(String version) throws CDOCException {
        switch (version) {
            case V1_0:
                return new CDOC10Builder();
            case V1_1:
                return new CDOC11Builder();
        }
        throw new CDOCException("Invalid version: " + version);
    }

    /**
     * Constructs an instance of {@link CDOCBuilder} for the default version of CDOC
     *
     * @throws CDOCException
     * @return an instance of {@link CDOCBuilder} for the default version of CDOC
     */
    public static CDOCBuilder defaultVersion() throws CDOCException {
        return version(V1_1);
    }

    /**
     * Adds data file
     *
     * @param dataFile to be encrypted
     * @return this builder
     */
    public CDOCBuilder withDataFile(DataFile dataFile) {
        dataFiles.add(dataFile);
        return this;
    }

    /**
     * Adds data file
     *
     * @param path of the file to be encrypted
     * @throws IOException when there's an error reading file from the given path
     * @return this builder
     */
    public CDOCBuilder withDataFile(Path path) throws IOException {
        return withDataFile(path.toFile());
    }

    /**
     * Adds data file
     *
     * @param file to be encrypted
     * @throws IOException when there's an error reading the given file
     * @return this builder
     */
    public CDOCBuilder withDataFile(File file) throws IOException {
        FileInputStream fis = new FileInputStream(file);
        DataFile dataFile = new DataFile(file.getName(), fis, file.length());
        return withDataFile(dataFile);
    }

    /**
     * Adds data file
     *
     * @param dataFiles to be encrypted
     * @return this builder
     */
    public CDOCBuilder withDataFiles(List<DataFile> dataFiles) {
        for (DataFile file : dataFiles) {
            withDataFile(file);
        }
        return this;
    }

    /**
     * Adds recipient
     *
     * @param certificate of the recipient
     * @throws RecipientCertificateException when the certificate doesn't qualify
     * @return this builder
     */
    public CDOCBuilder withRecipient(X509Certificate certificate) throws RecipientCertificateException {
        validateRecipientCertificate(certificate);
        recipients.add(certificate);
        return this;
    }

    /**
     * Adds recipient
     *
     * @param inputStream of the recipient's certificate
     * @throws RecipientCertificateException when there's an error reading the certificate from input stream or when the certificate doesn't qualify
     * @return this builder
     */
    public CDOCBuilder withRecipient(InputStream inputStream) throws RecipientCertificateException {
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(inputStream);
            return withRecipient(certificate);
        } catch (CertificateException e) {
            String message = "Error reading certificate from input stream!";
            LOGGER.error(message, e);
            throw new RecipientCertificateException(message, e);
        } finally {
            IOUtils.closeQuietly(inputStream);
        }
    }

    /**
     * Adds recipients
     *
     * @param certificates of the recipients
     * @throws RecipientCertificateException when at least one the certificates doesn't qualify
     * @return this builder
     */
    public CDOCBuilder withRecipients(List<X509Certificate> certificates) throws RecipientCertificateException {
        for (X509Certificate certificate : certificates) {
            withRecipient(certificate);
        }
        return this;
    }

    public void buildToFile(File file) throws CDOCException, FileNotFoundException {
        this.output = new FileOutputStream(file);
        build();
    }

    public void buildToOutputStream(OutputStream outputStream) throws CDOCException {
        this.output = outputStream;
        build();
    }

    /**
     * builds the CDOC
     *
     * @return cdoc content bytes
     * @throws CDOCException when there is an error building CDOC
     */
    abstract void build() throws CDOCException;

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
