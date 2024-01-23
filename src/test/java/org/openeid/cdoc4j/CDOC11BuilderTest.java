package org.openeid.cdoc4j;

import org.junit.jupiter.api.Test;
import org.openeid.cdoc4j.exception.CDOCException;
import org.openeid.cdoc4j.exception.DataFileMissingException;
import org.openeid.cdoc4j.exception.RecipientCertificateException;
import org.openeid.cdoc4j.exception.RecipientMissingException;

import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.openeid.cdoc4j.TestUtil.assertStreamClosed;
import static org.openeid.cdoc4j.TestUtil.mockDataFile;

class CDOC11BuilderTest {

    private final String version = "1.1";
    private final String testFileName = "test.txt";
    private InputStream rsaAuthCertificate = getClass().getResourceAsStream("/rsa/auth_cert.pem");
    private InputStream rsaSignCertificate = getClass().getResourceAsStream("/rsa/sign_cert.pem");
    private InputStream eccAuthCertificate = getClass().getResourceAsStream("/ecc/auth_cert.pem");
    private InputStream eccSignCertificate = getClass().getResourceAsStream("/ecc/sign_cert.pem");

    @Test
    void buildCDOC11_withoutRecipient_shouldThrowException() throws Exception {
        DataFile dataFile = mockDataFile("test".getBytes());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CDOCBuilder builder = CDOCBuilder
                .version(version)
                .withDataFile(dataFile);

        RecipientMissingException caughtException = assertThrows(
                RecipientMissingException.class,
                () -> builder.buildToOutputStream(baos)
        );

        assertEquals("CDOC Must contain at least 1 recipient!", caughtException.getMessage());
    }

    @Test
    void buildCDOC11_withoutDataFile_shouldThrowException() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataFileMissingException caughtException;
        CDOCBuilder builder = CDOCBuilder
                .version(version)
                .withRecipient(rsaAuthCertificate);

        try {
            caughtException = assertThrows(
                    DataFileMissingException.class,
                    () -> builder.buildToOutputStream(baos)
            );
        } finally {
            assertStreamClosed(rsaAuthCertificate);
        }

        assertEquals("CDOC Must contain at least 1 data file!", caughtException.getMessage());
    }

    @Test
    void buildCDOC11_withRecipientCertificateMissingKeyEnciphermentKeyUsage_shouldThrowException() throws Exception {
        DataFile dataFile = mockDataFile("test".getBytes());
        CDOCBuilder builder = CDOCBuilder
                .version(version)
                .withDataFile(dataFile);

        RecipientCertificateException caughtException = assertThrows(
                RecipientCertificateException.class,
                () -> builder.withRecipient(rsaSignCertificate)
        );

        assertEquals("Recipient's certificate doesn't contain 'keyEncipherment' key usage!", caughtException.getMessage());
    }

    @Test
    void buildCDOC11_withRecipientECCertificateMissingKeyAgreementKeyUsage_shouldThrowException() throws Exception {
        DataFile dataFile = mockDataFile("test".getBytes());
        RecipientCertificateException caughtException;
        CDOCBuilder builder = CDOCBuilder
                .version(version)
                .withDataFile(dataFile);

        try {
            caughtException = assertThrows(
                    RecipientCertificateException.class,
                    () -> builder.withRecipient(eccSignCertificate)
            );
        } finally {
            assertStreamClosed(eccSignCertificate);
        }

        assertEquals("Recipient's certificate doesn't contain 'keyAgreement' key usage!", caughtException.getMessage());
    }

    @Test
    void buildCDOC11_withRSACertificate_toByteArray_withSingleFile_shouldSucceed() throws CDOCException {
        DataFile dataFile = new DataFile(testFileName, "test data content".getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CDOCBuilder.version(version)
                .withDataFile(dataFile)
                .withRecipient(rsaAuthCertificate)
                .buildToOutputStream(baos);

        assertEquals(3658, baos.size());
        assertStreamClosed(dataFile.getContent());
        assertStreamClosed(rsaAuthCertificate);
    }

    @Test
    void buildCDOC11_withECCertificate_toByteArrayStream_withSingleFile_shouldSucceed() throws CDOCException {
        DataFile dataFile = new DataFile(testFileName, "test data content".getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CDOCBuilder.version(version)
                .withDataFile(dataFile)
                .withRecipient(eccAuthCertificate)
                .buildToOutputStream(baos);

        assertEquals(7998, baos.size());
        assertStreamClosed(dataFile.getContent());
        assertStreamClosed(eccAuthCertificate);
    }

    @Test
    void buildCDOC11_withRSACertificate_toByteArrayStream_withDDOC_shouldSucceed() throws CDOCException {
        List<DataFile> dataFiles = Arrays.asList(
                new DataFile(testFileName, "some test content".getBytes(StandardCharsets.UTF_8)),
                new DataFile(testFileName, "other test content".getBytes(StandardCharsets.UTF_8))
        );
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CDOCBuilder.version(version)
                .withDataFiles(dataFiles)
                .withRecipient(rsaAuthCertificate)
                .buildToOutputStream(baos);

        assertEquals(4492, baos.size());

        for (DataFile dataFile : dataFiles) {
            assertStreamClosed(dataFile.getContent());
        }
        assertStreamClosed(rsaAuthCertificate);
    }

    @Test
    void buildCDOC11_withRSACertificate_toFile_withSingleFile_shouldSucceed() throws CDOCException, IOException {
        File destinationFile = new File("target/cdoc11-rsa-with-single-file.cdoc");

        DataFile dataFile = new DataFile(testFileName, "some-test-data".getBytes(StandardCharsets.UTF_8));
        CDOCBuilder.version(version)
                .withDataFile(dataFile)
                .withRecipient(rsaAuthCertificate)
                .buildToFile(destinationFile);

        assertEquals(3654, destinationFile.length());
        assertStreamClosed(dataFile.getContent());
        assertStreamClosed(rsaAuthCertificate);
    }

    @Test
    void buildCDOC11_withRSACertificate_toFile_withDDOC_shouldSucceed() throws CDOCException, IOException {
        File destinationFile = new File("target/cdoc11-rsa-with-DDOC2.cdoc");

        List<DataFile> dataFiles = Arrays.asList(
                new DataFile(testFileName, "some-test-data".getBytes(StandardCharsets.UTF_8)),
                new DataFile(testFileName, "some-other-test-data".getBytes(StandardCharsets.UTF_8))
        );

        CDOCBuilder.version(version)
                .withDataFiles(dataFiles)
                .withRecipient(rsaAuthCertificate)
                .buildToFile(destinationFile);

        assertEquals(4492, destinationFile.length());
        for (DataFile dataFile : dataFiles) {
            assertStreamClosed(dataFile.getContent());
        }
        assertStreamClosed(rsaAuthCertificate);
    }

    @Test
    void buildCDOC11_withRSACertificate_toOutputStream_withDDOC_shouldSucceed() throws CDOCException, IOException {
        try (
            ByteArrayOutputStream output = new ByteArrayOutputStream()
        ) {
            List<DataFile> dataFiles = Arrays.asList(
                    new DataFile(testFileName, "some-test-data".getBytes(StandardCharsets.UTF_8)),
                    new DataFile(testFileName, "some-other-test-data".getBytes(StandardCharsets.UTF_8))
            );

            CDOCBuilder.version(version)
                    .withDataFiles(dataFiles)
                    .withRecipient(rsaAuthCertificate)
                    .buildToOutputStream(output);

            assertEquals(4492, output.size());
            for (DataFile dataFile : dataFiles) {
                assertStreamClosed(dataFile.getContent());
            }
            assertStreamClosed(rsaAuthCertificate);
        }
    }

    @Test
    void buildCDOC11_95megabytesFile() throws CDOCException, IOException {
        InputStream certificateInputStream = getClass().getResourceAsStream("/rsa/auth_cert.pem");

        File tempFile = File.createTempFile("bigFile", "-95megabytes");
        BufferedWriter bw = new BufferedWriter(new FileWriter(tempFile));
        for (int i = 0; i < 10000000; i++) {
            bw.write("aaaaaaaaaa");
        }
        bw.close();


        File fileDestination = new File("target/cdoc10_withBigFile.cdoc");
        CDOCBuilder.version(version)
                .withDataFile(tempFile)
                .withRecipient(certificateInputStream)
                .buildToFile(fileDestination);

        fileDestination.deleteOnExit();
        tempFile.deleteOnExit();
    }
} 
