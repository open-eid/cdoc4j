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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.openeid.cdoc4j.TestUtil.assertStreamClosed;
import static org.openeid.cdoc4j.TestUtil.mockDataFile;

class CDOC10BuilderTest {

    private final String version = "1.0";
    private final String testFileName = "test.txt";
    private InputStream certificateInputStream;

    @Test
    void buildCDOC10_withoutRecipient_shouldThrowException() throws Exception {
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
    void buildCDOC10_withoutDataFile_shouldThrowException() throws Exception {
        DataFileMissingException caughtException;

        try {
            certificateInputStream = getClass().getResourceAsStream("/rsa/auth_cert.pem");
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            CDOCBuilder builder = CDOCBuilder
                    .version(version)
                    .withRecipient(certificateInputStream);

            caughtException = assertThrows(
                    DataFileMissingException.class,
                    () -> builder.buildToOutputStream(baos)
            );
        } finally {
            assertStreamClosed(certificateInputStream);
        }

        assertEquals("CDOC Must contain at least 1 data file!", caughtException.getMessage());
    }

    @Test
    void buildCDOC10_withRecipientCertificateMissingKeyEnciphermentKeyUsage_shouldThrowException() throws Exception {
        DataFile dataFile = mockDataFile("test".getBytes());
        RecipientCertificateException caughtException;

        try {
            certificateInputStream = getClass().getResourceAsStream("/rsa/sign_cert.pem");
            CDOCBuilder builder = CDOCBuilder
                    .version(version)
                    .withDataFile(dataFile);

            caughtException = assertThrows(
                    RecipientCertificateException.class,
                    () -> builder.withRecipient(certificateInputStream)
            );
        } finally {
            assertStreamClosed(certificateInputStream);
        }

        assertEquals("Recipient's certificate doesn't contain 'keyEncipherment' key usage!", caughtException.getMessage());
    }

    @Test
    void buildCDOC10_withECCertificate_shouldThrowException() throws Exception {
        DataFile dataFile = mockDataFile("test".getBytes());
        RecipientCertificateException caughtException;

        try {
            certificateInputStream = getClass().getResourceAsStream("/ecc/auth_cert.pem");
            CDOCBuilder builder = CDOCBuilder
                    .version(version)
                    .withDataFile(dataFile);

            caughtException = assertThrows(
                    RecipientCertificateException.class,
                    () -> builder.withRecipient(certificateInputStream)
            );
        } finally {
            assertStreamClosed(certificateInputStream);
        }

        assertEquals("CDOC 1.0 only supports RSA keys!", caughtException.getMessage());
    }

    @Test
    void buildCDOC10_withRSACertificate_toByteArray_withSingleFile_shouldSucceed() throws CDOCException {
        certificateInputStream = getClass().getResourceAsStream("/rsa/auth_cert.pem");
        DataFile dataFile = new DataFile(testFileName, "test data content".getBytes(StandardCharsets.UTF_8));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CDOCBuilder.version(version)
                .withDataFile(dataFile)
                .withRecipient(certificateInputStream)
                .buildToOutputStream(baos);

        assertEquals(3689, baos.toByteArray().length);
        assertStreamClosed(dataFile.getContent());
        assertStreamClosed(certificateInputStream);
    }

    @Test
    void buildCDOC10_withRSACertificate_toByteArrayStream_withSingleFile_shouldSucceed() throws CDOCException {
        certificateInputStream = getClass().getResourceAsStream("/rsa/auth_cert.pem");

        DataFile dataFile = new DataFile(testFileName, "some-test-data".getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CDOCBuilder.version(version)
                .withDataFile(dataFile)
                .withRecipient(certificateInputStream)
                .buildToOutputStream(baos);

        assertEquals(3663, baos.size());
        assertStreamClosed(dataFile.getContent());
        assertStreamClosed(certificateInputStream);
    }

    @Test
    void buildCDOC10_withRSACertificate_toByteArrayStream_withDDOC_shouldSucceed() throws CDOCException {
        certificateInputStream = getClass().getResourceAsStream("/rsa/auth_cert.pem");

        List<DataFile> dataFiles = Arrays.asList(
                new DataFile(testFileName, "some-test-data".getBytes(StandardCharsets.UTF_8)),
                new DataFile(testFileName, "some-other-test-data".getBytes(StandardCharsets.UTF_8))
        );
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CDOCBuilder.version(version)
                .withDataFile(dataFiles.get(0))
                .withDataFile(dataFiles.get(1))
                .withRecipient(certificateInputStream)
                .buildToOutputStream(baos);

        assertEquals(4519, baos.size());

        for (DataFile dataFile : dataFiles) {
            assertStreamClosed(dataFile.getContent());
        }
        assertStreamClosed(certificateInputStream);
    }

    @Test
    void buildCDOC10_withRSACertificate_toFile_withSingleFile_shouldSucceed() throws CDOCException, IOException {
        certificateInputStream = getClass().getResourceAsStream("/rsa/auth_cert.pem");
        File destinationFile = new File("target/cdoc10-rsa-with-single-file.cdoc");

        DataFile dataFile = new DataFile(testFileName, "some-test-data".getBytes(StandardCharsets.UTF_8));
        CDOCBuilder.version(version)
                .withDataFile(dataFile)
                .withRecipient(certificateInputStream)
                .buildToFile(destinationFile);

        assertEquals(3663, destinationFile.length());
        assertStreamClosed(dataFile.getContent());
        assertStreamClosed(certificateInputStream);
    }

    @Test
    void buildCDOC10_withRSACertificate_toFile_withDDOC_shouldSucceed() throws CDOCException, IOException {
        certificateInputStream = getClass().getResourceAsStream("/rsa/auth_cert.pem");
        File destinationFile = new File("target/cdoc10-rsa-with-DDOC2.cdoc");

        List<DataFile> dataFiles = Arrays.asList(
                new DataFile(testFileName, "some-test-data".getBytes(StandardCharsets.UTF_8)),
                new DataFile(testFileName, "some-other-test-data".getBytes(StandardCharsets.UTF_8))
        );

        CDOCBuilder.version(version)
                .withDataFile(dataFiles.get(0))
                .withDataFile(dataFiles.get(1))
                .withRecipient(certificateInputStream)
                .buildToFile(destinationFile);

        assertEquals(4519, destinationFile.length());
        for (DataFile dataFile : dataFiles) {
            assertStreamClosed(dataFile.getContent());
        }
        assertStreamClosed(certificateInputStream);
    }

    @Test
    void buildCDOC10_withRSACertificate_toOutputStream_withDDOC_shouldSucceed() throws CDOCException, IOException {
        certificateInputStream = getClass().getResourceAsStream("/rsa/auth_cert.pem");

        try (
            ByteArrayOutputStream output = new ByteArrayOutputStream()
        ) {
            List<DataFile> dataFiles = Arrays.asList(
                    new DataFile(testFileName, "some-test-data".getBytes(StandardCharsets.UTF_8)),
                    new DataFile(testFileName, "some-other-test-data".getBytes(StandardCharsets.UTF_8))
            );

            CDOCBuilder.version(version)
                    .withDataFile(dataFiles.get(0))
                    .withDataFile(dataFiles.get(1))
                    .withRecipient(certificateInputStream)
                    .buildToOutputStream(output);

            assertEquals(4519, output.size());
            for (DataFile dataFile : dataFiles) {
                assertStreamClosed(dataFile.getContent());
            }
            assertStreamClosed(certificateInputStream);
        }
    }

    @Test
    void buildCDOC10_emptyFile() throws CDOCException, IOException {
        certificateInputStream = getClass().getResourceAsStream("/rsa/auth_cert.pem");

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CDOCBuilder.version(version)
                .withDataFile(new File("src/test/resources/cdoc/empty_file.txt"))
                .withRecipient(certificateInputStream)
                .buildToOutputStream(baos);

        assertNotNull(baos.toByteArray());
    }

    @Test
    void buildCDOC10_95megabytesFile() throws CDOCException, IOException {
        certificateInputStream = getClass().getResourceAsStream("/rsa/auth_cert.pem");

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
