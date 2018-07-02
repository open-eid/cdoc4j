package org.openeid.cdoc4j;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.openeid.cdoc4j.exception.CDOCException;
import org.openeid.cdoc4j.exception.DataFileMissingException;
import org.openeid.cdoc4j.exception.RecipientCertificateException;
import org.openeid.cdoc4j.exception.RecipientMissingException;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;
import static org.openeid.cdoc4j.TestLogMemory.logMemoryUsage;
import static org.openeid.cdoc4j.TestUtil.assertStreamClosed;
import static org.openeid.cdoc4j.TestUtil.mockDataFile;

public class CDOC10BuilderTest {

    private final String version = "1.0";
    private final String testFileName = "test.txt";
    private InputStream certificateInputStream;

    @Before
    public void init() {
        logMemoryUsage("START 1");
    }

    @After
    public void after() {
        logMemoryUsage("END");
        if (certificateInputStream != null) {
            try {
                certificateInputStream.close();
            } catch (IOException e) {
                fail("Failed to close stream");
            }
        }
    }

    @Test(expected = RecipientMissingException.class)
    public void buildCDOC10_withoutRecipient_shouldThrowException() throws CDOCException {
        DataFile dataFile = mockDataFile("test".getBytes());
        try {
            CDOCBuilder.version(version)
                    .withDataFile(dataFile)
                    .buildToByteArrayInputStream();
        } finally {
            assertStreamClosed(dataFile.getContent());
        }
    }

    @Test(expected = DataFileMissingException.class)
    public void buildCDOC10_withoutDataFile_shouldThrowException() throws CDOCException {
        try {
            certificateInputStream = getClass().getResourceAsStream("/rsa/auth_cert.pem");
            CDOCBuilder.version(version)
                    .withRecipient(certificateInputStream)
                    .buildToByteArrayInputStream();
        } finally {
            assertStreamClosed(certificateInputStream);
        }

    }

    @Test(expected = RecipientCertificateException.class)
    public void buildCDOC10_withRecipientCertificateMissingKeyEnciphermentKeyUsage_shouldThrowException() throws CDOCException {
        DataFile dataFile = mockDataFile("test".getBytes());
        try {
            certificateInputStream = getClass().getResourceAsStream("/rsa/sign_cert.pem");
            CDOCBuilder.version(version)
                    .withDataFile(dataFile)
                    .withRecipient(certificateInputStream)
                    .buildToByteArrayInputStream();
        } finally {
            assertStreamClosed(certificateInputStream);
            assertStreamClosed(dataFile.getContent());
        }

    }

    @Test(expected = RecipientCertificateException.class)
    public void buildCDOC10_withECCertificate_shouldThrowException() throws CDOCException {
        DataFile dataFile = mockDataFile("test".getBytes());
        try {
            certificateInputStream = getClass().getResourceAsStream("/ecc/auth_cert.pem");
            CDOCBuilder.version(version)
                    .withDataFile(dataFile)
                    .withRecipient(certificateInputStream)
                    .buildToByteArrayInputStream();
        } finally {
            assertStreamClosed(certificateInputStream);
            assertStreamClosed(dataFile.getContent());
        }
    }

    @Test
    public void buildCDOC10_withRSACertificate_toByteArray_withSingleFile_shouldSucceed() throws CDOCException {
        certificateInputStream = getClass().getResourceAsStream("/rsa/auth_cert.pem");
        DataFile dataFile = new DataFile(testFileName, "test data content".getBytes(StandardCharsets.UTF_8));
        byte[] cdocBytes = CDOCBuilder.version(version)
                .withDataFile(dataFile)
                .withRecipient(certificateInputStream)
                .buildToByteArray();

        assertEquals(3692, cdocBytes.length);
        assertStreamClosed(dataFile.getContent());
        assertStreamClosed(certificateInputStream);
    }

    @Test
    public void buildCDOC10_withRSACertificate_toByteArrayStream_withSingleFile_shouldSucceed() throws CDOCException, IOException {
        certificateInputStream = getClass().getResourceAsStream("/rsa/auth_cert.pem");

        try (
            ByteArrayInputStream fileToDecrypt = new ByteArrayInputStream("some-test-data".getBytes(StandardCharsets.UTF_8));
        ) {
            DataFile dataFile = new DataFile(testFileName, fileToDecrypt);
            InputStream CDOCStream = CDOCBuilder.version(version)
                    .withDataFile(dataFile)
                    .withRecipient(certificateInputStream)
                    .buildToByteArrayInputStream();

            assertTrue(CDOCStream instanceof ByteArrayInputStream);
            int contentLength = ((ByteArrayInputStream) CDOCStream).available();
            assertEquals(3666, contentLength);
            assertStreamClosed(dataFile.getContent());
            assertStreamClosed(certificateInputStream);

            CDOCStream.close();
        }
    }

    @Test
    public void buildCDOC10_withRSACertificate_toByteArrayStream_withDDOC_shouldSucceed() throws CDOCException, IOException {
        certificateInputStream = getClass().getResourceAsStream("/rsa/auth_cert.pem");

        try (
            ByteArrayInputStream fileToDecrypt = new ByteArrayInputStream("some-test-data".getBytes(StandardCharsets.UTF_8));
            ByteArrayInputStream fileToDecrypt2 = new ByteArrayInputStream("some-other-test-data".getBytes(StandardCharsets.UTF_8))
        ) {
            List<DataFile> dataFiles = Arrays.asList(
                    new DataFile(testFileName, fileToDecrypt),
                    new DataFile(testFileName, fileToDecrypt2)
            );

            InputStream CDOCStream = CDOCBuilder.version(version)
                    .withDataFiles(dataFiles)
                    .withRecipient(certificateInputStream)
                    .buildToByteArrayInputStream();

            assertTrue(CDOCStream instanceof ByteArrayInputStream);
            int contentLength = ((ByteArrayInputStream) CDOCStream).available();
            assertEquals(4414, contentLength);

            for (DataFile dataFile : dataFiles) {
                assertStreamClosed(dataFile.getContent());
            }
            assertStreamClosed(certificateInputStream);
            CDOCStream.close();
        }
    }

    @Test
    public void buildCDOC10_withRSACertificate_toFile_withSingleFile_shouldSucceed() throws CDOCException, IOException {
        certificateInputStream = getClass().getResourceAsStream("/rsa/auth_cert.pem");
        File destinationFile = new File("target/cdoc10-rsa-with-single-file.cdoc");

        try (
            ByteArrayInputStream fileToDecrypt = new ByteArrayInputStream("some-test-data".getBytes(StandardCharsets.UTF_8));
        ) {
            DataFile dataFile = new DataFile(testFileName, fileToDecrypt);
            CDOCBuilder.version(version)
                    .withDataFile(dataFile)
                    .withRecipient(certificateInputStream)
                    .buildToFile(destinationFile);

            assertEquals(3666, destinationFile.length());
            assertStreamClosed(dataFile.getContent());
            assertStreamClosed(certificateInputStream);
        }
    }

    @Test
    public void buildCDOC10_withRSACertificate_toFile_withDDOC_shouldSucceed() throws CDOCException, IOException {
        certificateInputStream = getClass().getResourceAsStream("/rsa/auth_cert.pem");
        File destinationFile = new File("target/cdoc10-rsa-with-DDOC2.cdoc");

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
                    .withRecipient(certificateInputStream)
                    .buildToFile(destinationFile);

            assertEquals(4414, destinationFile.length());
            for (DataFile dataFile : dataFiles) {
                assertStreamClosed(dataFile.getContent());
            }
            assertStreamClosed(certificateInputStream);
        }
    }

    @Test
    public void buildCDOC10_withRSACertificate_toOutputStream_withDDOC_shouldSucceed() throws CDOCException, IOException {
        certificateInputStream = getClass().getResourceAsStream("/rsa/auth_cert.pem");

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
                    .withRecipient(certificateInputStream)
                    .buildToOutputStream(output);

            assertEquals(4414, output.size());
            for (DataFile dataFile : dataFiles) {
                assertStreamClosed(dataFile.getContent());
            }
            assertStreamClosed(certificateInputStream);
        }
    }

    @Test
    public void buildCDOC10_emptyFile() throws CDOCException, IOException {
        certificateInputStream = getClass().getResourceAsStream("/rsa/auth_cert.pem");

        byte[] cdocBytes = CDOCBuilder.version(version)
                .withDataFile(new File("src/test/resources/cdoc/empty_file.txt"))
                .withRecipient(certificateInputStream)
                .buildToByteArray();

        assertNotNull(cdocBytes);
    }

    @Test
    public void buildCDOC10_95megabytesFile() throws CDOCException, IOException {
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
