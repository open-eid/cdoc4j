package org.openeid.cdoc4j;

import org.junit.Test;
import org.openeid.cdoc4j.exception.CDOCException;
import org.openeid.cdoc4j.exception.DataFileMissingException;
import org.openeid.cdoc4j.exception.RecipientCertificateException;
import org.openeid.cdoc4j.exception.RecipientMissingException;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.openeid.cdoc4j.TestUtil.assertStreamClosed;
import static org.openeid.cdoc4j.TestUtil.mockDataFile;

public class CDOC11BuilderTest {

    private final String version = "1.1";
    private final String testFileName = "test.txt";
    private InputStream rsaAuthCertificate = getClass().getResourceAsStream("/rsa/auth_cert.pem");
    private InputStream rsaSignCertificate = getClass().getResourceAsStream("/rsa/sign_cert.pem");
    private InputStream eccAuthCertificate = getClass().getResourceAsStream("/ecc/auth_cert.pem");
    private InputStream eccSignCertificate = getClass().getResourceAsStream("/ecc/sign_cert.pem");

    @Test(expected = RecipientMissingException.class)
    public void buildCDOC11_withoutRecipient_shouldThrowException() throws CDOCException {
        DataFile dataFile = mockDataFile("test".getBytes());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CDOCBuilder.version(version)
                .withDataFile(dataFile)
                .buildToOutputStream(baos);
    }

    @Test(expected = DataFileMissingException.class)
    public void buildCDOC11_withoutDataFile_shouldThrowException() throws CDOCException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            CDOCBuilder.version(version)
                    .withRecipient(rsaAuthCertificate)
                    .buildToOutputStream(baos);
        } finally {
            assertStreamClosed(rsaAuthCertificate);
        }
    }

    @Test(expected = RecipientCertificateException.class)
    public void buildCDOC11_withRecipientCertificateMissingKeyEnciphermentKeyUsage_shouldThrowException() throws CDOCException {
        DataFile dataFile = mockDataFile("test".getBytes());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CDOCBuilder.version(version)
                    .withDataFile(dataFile)
                    .withRecipient(rsaSignCertificate)
                    .buildToOutputStream(baos);
    }

    @Test(expected = RecipientCertificateException.class)
    public void buildCDOC11_withRecipientECCertificateMissingKeyAgreementKeyUsage_shouldThrowException() throws CDOCException {
        DataFile dataFile = mockDataFile("test".getBytes());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            CDOCBuilder.version(version)
                    .withDataFile(dataFile)
                    .withRecipient(eccSignCertificate)
                    .buildToOutputStream(baos);
        } finally {
            assertStreamClosed(eccSignCertificate);
        }
    }

    @Test
    public void buildCDOC11_withRSACertificate_toByteArray_withSingleFile_shouldSucceed() throws CDOCException {
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
    public void buildCDOC11_withECCertificate_toByteArrayStream_withSingleFile_shouldSucceed() throws CDOCException, IOException {
        try (
            ByteArrayInputStream fileToDecrypt = new ByteArrayInputStream("test data content".getBytes(StandardCharsets.UTF_8));
        ) {
            DataFile dataFile = new DataFile(testFileName, fileToDecrypt);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            CDOCBuilder.version(version)
                    .withDataFile(dataFile)
                    .withRecipient(eccAuthCertificate)
                    .buildToOutputStream(baos);

            assertEquals(7998, baos.size());
            assertStreamClosed(dataFile.getContent());
            assertStreamClosed(eccAuthCertificate);
        }
    }

    @Test
    public void buildCDOC11_withRSACertificate_toByteArrayStream_withDDOC_shouldSucceed() throws CDOCException, IOException {

        try (
            ByteArrayInputStream fileToDecrypt = new ByteArrayInputStream("some test content".getBytes(StandardCharsets.UTF_8));
            ByteArrayInputStream fileToDecrypt2 = new ByteArrayInputStream("other test content".getBytes(StandardCharsets.UTF_8))
        ) {
            List<DataFile> dataFiles = Arrays.asList(
                    new DataFile(testFileName, fileToDecrypt),
                    new DataFile(testFileName, fileToDecrypt2)
            );
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            CDOCBuilder.version(version)
                    .withDataFiles(dataFiles)
                    .withRecipient(rsaAuthCertificate)
                    .buildToOutputStream(baos);

            assertEquals(4382, baos.size());

            for (DataFile dataFile : dataFiles) {
                assertStreamClosed(dataFile.getContent());
            }
            assertStreamClosed(rsaAuthCertificate);
        }
    }

    @Test
    public void buildCDOC11_withRSACertificate_toFile_withSingleFile_shouldSucceed() throws CDOCException, IOException {
        File destinationFile = new File("target/cdoc11-rsa-with-single-file.cdoc");

        try (
            ByteArrayInputStream fileToDecrypt = new ByteArrayInputStream("some-test-data".getBytes(StandardCharsets.UTF_8));
        ) {
            DataFile dataFile = new DataFile(testFileName, fileToDecrypt);
            CDOCBuilder.version(version)
                    .withDataFile(dataFile)
                    .withRecipient(rsaAuthCertificate)
                    .buildToFile(destinationFile);

            assertEquals(3654, destinationFile.length());
            assertStreamClosed(dataFile.getContent());
            assertStreamClosed(rsaAuthCertificate);
        }
    }

    @Test
    public void buildCDOC11_withRSACertificate_toFile_withDDOC_shouldSucceed() throws CDOCException, IOException {
        File destinationFile = new File("target/cdoc11-rsa-with-DDOC2.cdoc");

        try (
            ByteArrayInputStream fileToDecrypt = new ByteArrayInputStream("some-test-data".getBytes(StandardCharsets.UTF_8));
            ByteArrayInputStream fileToDecrypt2 = new ByteArrayInputStream("some-other-test-data".getBytes(StandardCharsets.UTF_8))
        ) {
            List<DataFile> dataFiles = Arrays.asList(
                    new DataFile(testFileName, fileToDecrypt),
                    new DataFile(testFileName, fileToDecrypt2)
            );

            CDOCBuilder.version(version)
                    .withDataFiles(dataFiles)
                    .withRecipient(rsaAuthCertificate)
                    .buildToFile(destinationFile);

            assertEquals(4382, destinationFile.length());
            for (DataFile dataFile : dataFiles) {
                assertStreamClosed(dataFile.getContent());
            }
            assertStreamClosed(rsaAuthCertificate);
        }
    }

    @Test
    public void buildCDOC11_withRSACertificate_toOutputStream_withDDOC_shouldSucceed() throws CDOCException, IOException {
        try (
            ByteArrayInputStream fileToDecrypt = new ByteArrayInputStream("some-test-data".getBytes(StandardCharsets.UTF_8));
            ByteArrayInputStream fileToDecrypt2 = new ByteArrayInputStream("some-other-test-data".getBytes(StandardCharsets.UTF_8));
            ByteArrayOutputStream output = new ByteArrayOutputStream()
        ) {
            List<DataFile> dataFiles = Arrays.asList(
                    new DataFile(testFileName, fileToDecrypt),
                    new DataFile(testFileName, fileToDecrypt2)
            );

            CDOCBuilder.version(version)
                    .withDataFiles(dataFiles)
                    .withRecipient(rsaAuthCertificate)
                    .buildToOutputStream(output);

            assertEquals(4382, output.size());
            for (DataFile dataFile : dataFiles) {
                assertStreamClosed(dataFile.getContent());
            }
            assertStreamClosed(rsaAuthCertificate);
        }
    }

    @Test
    public void buildCDOC11_95megabytesFile() throws CDOCException, IOException {
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
