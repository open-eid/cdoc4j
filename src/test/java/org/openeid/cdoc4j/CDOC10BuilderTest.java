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

import static org.junit.Assert.*;
import static org.openeid.cdoc4j.TestUtil.assertStreamClosed;
import static org.openeid.cdoc4j.TestUtil.mockDataFile;

public class CDOC10BuilderTest {

    private final String version = "1.0";
    private final String testFileName = "test.txt";
    private InputStream certificateInputStream;

    @Test(expected = RecipientMissingException.class)
    public void buildCDOC10_withoutRecipient_shouldThrowException() throws CDOCException {
        DataFile dataFile = mockDataFile("test".getBytes());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CDOCBuilder.version(version)
                    .withDataFile(dataFile)
                    .buildToOutputStream(baos);
    }

    @Test(expected = DataFileMissingException.class)
    public void buildCDOC10_withoutDataFile_shouldThrowException() throws CDOCException {
        try {
            certificateInputStream = getClass().getResourceAsStream("/rsa/auth_cert.pem");
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            CDOCBuilder.version(version)
                    .withRecipient(certificateInputStream)
                    .buildToOutputStream(baos);
        } finally {
            assertStreamClosed(certificateInputStream);
        }

    }

    @Test(expected = RecipientCertificateException.class)
    public void buildCDOC10_withRecipientCertificateMissingKeyEnciphermentKeyUsage_shouldThrowException() throws CDOCException {
        DataFile dataFile = mockDataFile("test".getBytes());
        try {
            certificateInputStream = getClass().getResourceAsStream("/rsa/sign_cert.pem");
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            CDOCBuilder.version(version)
                    .withDataFile(dataFile)
                    .withRecipient(certificateInputStream)
                    .buildToOutputStream(baos);
        } finally {
            assertStreamClosed(certificateInputStream);
        }

    }

    @Test(expected = RecipientCertificateException.class)
    public void buildCDOC10_withECCertificate_shouldThrowException() throws CDOCException {
        DataFile dataFile = mockDataFile("test".getBytes());
        try {
            certificateInputStream = getClass().getResourceAsStream("/ecc/auth_cert.pem");
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            CDOCBuilder.version(version)
                    .withDataFile(dataFile)
                    .withRecipient(certificateInputStream)
                    .buildToOutputStream(baos);
        } finally {
            assertStreamClosed(certificateInputStream);
        }
    }

    @Test
    public void buildCDOC10_withRSACertificate_toByteArray_withSingleFile_shouldSucceed() throws CDOCException {
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
    public void buildCDOC10_withRSACertificate_toByteArrayStream_withSingleFile_shouldSucceed() throws CDOCException, IOException {
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
    public void buildCDOC10_withRSACertificate_toByteArrayStream_withDDOC_shouldSucceed() throws CDOCException, IOException {
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
    public void buildCDOC10_withRSACertificate_toFile_withSingleFile_shouldSucceed() throws CDOCException, IOException {
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
    public void buildCDOC10_withRSACertificate_toFile_withDDOC_shouldSucceed() throws CDOCException, IOException {
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
    public void buildCDOC10_withRSACertificate_toOutputStream_withDDOC_shouldSucceed() throws CDOCException, IOException {
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
    public void buildCDOC10_emptyFile() throws CDOCException, IOException {
        certificateInputStream = getClass().getResourceAsStream("/rsa/auth_cert.pem");

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CDOCBuilder.version(version)
                .withDataFile(new File("src/test/resources/cdoc/empty_file.txt"))
                .withRecipient(certificateInputStream)
                .buildToOutputStream(baos);

        assertNotNull(baos.toByteArray());
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
