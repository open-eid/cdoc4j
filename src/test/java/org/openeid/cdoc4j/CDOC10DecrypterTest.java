package org.openeid.cdoc4j;

import static org.junit.Assert.*;
import static org.openeid.cdoc4j.TestUtil.*;

import org.junit.Ignore;
import org.junit.Test;
import org.openeid.cdoc4j.exception.CDOCException;
import org.openeid.cdoc4j.exception.DecryptionException;
import org.openeid.cdoc4j.token.pkcs12.PKCS12Token;
import org.openeid.cdoc4j.xml.exception.XmlParseException;

import java.io.*;
import java.util.Arrays;
import java.util.List;

public class CDOC10DecrypterTest {

    private final String version = "1.0";
    private final String testFileName = "test.txt";

    @Test(expected = DecryptionException.class)
    public void decryptCDOC10_withoutToken_shouldThrowException() throws CDOCException, FileNotFoundException {
        FileInputStream cdocInputStream = new FileInputStream("src/test/resources/cdoc/valid_cdoc10.cdoc");
        new CDOCDecrypter()
                .withCDOC(cdocInputStream)
                .decrypt(new File("target/testdata"));
    }

    @Test(expected = DecryptionException.class)
    public void decryptCDOC10_withoutCDOC_shouldThrowException() throws CDOCException, FileNotFoundException {
        new CDOCDecrypter()
                .withToken(new PKCS12Token(new FileInputStream("src/test/resources/rsa/rsa.p12"), "test"))
                .decrypt(new File("target/testdata"));
    }

    @Test(expected = FileNotFoundException.class)
    public void decryptCDOC10_CDOCFileNotFound_shouldThrowException() throws CDOCException, FileNotFoundException {
        FileInputStream fileInputStream = new FileInputStream("src/test/resources/cdoc/non_existing.cdoc");
        try {
            new CDOCDecrypter()
                    .withToken(new PKCS12Token(new FileInputStream("src/test/resources/rsa/rsa.p12"), "test"))
                    .withCDOC(fileInputStream)
                    .decrypt(new File("target/testdata"));
        } finally {
            assertStreamClosed(fileInputStream);
        }
    }

    @Test(expected = DecryptionException.class)
    public void decryptCDOC10_buildToDirectory_destinationIsNotDirectory_shouldThrowException() throws CDOCException, FileNotFoundException {
        FileInputStream cdocInputStream = new FileInputStream("src/test/resources/cdoc/valid_cdoc10.cdoc");
        try {
            new CDOCDecrypter()
                    .withToken(new PKCS12Token(new FileInputStream("src/test/resources/rsa/rsa.p12"), "test"))
                    .withCDOC(cdocInputStream)
                    .decrypt(new File("src/test/resources/rsa/rsa.p12"));
        } finally {
            assertStreamClosed(cdocInputStream);
        }
    }

    @Test
    public void decryptValidCDOC10_withSingleFile_shouldSucceed() throws Exception {
        FileInputStream cdocInputStream = new FileInputStream("src/test/resources/cdoc/valid_cdoc10.cdoc");
        List<File> dataFiles = new CDOCDecrypter()
                .withToken(new PKCS12Token(new FileInputStream("src/test/resources/rsa/rsa.p12"), "test"))
                .withCDOC(cdocInputStream)
                .decrypt(new File("target/testdata"));

        assertSame(1, dataFiles.size());
        assertFileDataFileContent(dataFiles.get(0), testFileName, "lorem ipsum");
        assertStreamClosed(cdocInputStream);
        deleteTestFiles(dataFiles);
    }

    @Test
    public void decryptValidCDOC10_toMemory_withSingleFile_shouldSucceed() throws Exception {

        FileInputStream cdocInputStream = new FileInputStream("src/test/resources/cdoc/valid_cdoc10.cdoc");
        List<DataFile> dataFiles = new CDOCDecrypter()
                .withToken(new PKCS12Token(new FileInputStream("src/test/resources/rsa/rsa.p12"), "test"))
                .withCDOC(cdocInputStream)
                .decrypt();

        assertSame(1, dataFiles.size());
        assertDataFileContent(dataFiles.get(0), testFileName, "lorem ipsum");
        assertStreamClosed(cdocInputStream);
    }

    @Test
    public void decryptValidCDOC10_withDDOCContaining2Files_shouldSucceed() throws Exception {
        PKCS12Token token = new PKCS12Token(new FileInputStream("src/test/resources/rsa/rsa.p12"), "test");

        FileInputStream cdocInputStream = new FileInputStream("src/test/resources/cdoc/valid_cdoc10_withDDOC.cdoc");
        List<File> dataFiles = new CDOCDecrypter()
                .withToken(token)
                .withCDOC(cdocInputStream)
                .decrypt(new File("target/testdata"));

        assertSame(2, dataFiles.size());
        assertFileDataFileContent(dataFiles.get(0), "lorem1.txt", "lorem ipsum");
        assertFileDataFileContent(dataFiles.get(1), "lorem2.txt", "Lorem ipsum dolor sit amet");
        assertStreamClosed(cdocInputStream);
        deleteTestFiles(dataFiles);
    }

    @Test
    public void decryptValidCDOC10_toMemory_withDDOCContaining2Files_shouldSucceed() throws Exception {
        PKCS12Token token = new PKCS12Token(new FileInputStream("src/test/resources/rsa/rsa.p12"), "test");

        FileInputStream cdocInputStream = new FileInputStream("src/test/resources/cdoc/valid_cdoc10_withDDOC.cdoc");
        List<DataFile> dataFiles = new CDOCDecrypter()
                .withToken(token)
                .withCDOC(cdocInputStream)
                .decrypt();

        assertSame(2, dataFiles.size());
        assertDataFileContent(dataFiles.get(0), "lorem1.txt", "lorem ipsum");
        assertDataFileContent(dataFiles.get(1), "lorem2.txt", "Lorem ipsum dolor sit amet");
        assertStreamClosed(cdocInputStream);
    }

    @Test
    public void buildAndDecryptCDOC10_RSA_fromMemory_toMemory_withSingleFile_shouldSucceed() throws Exception {
        String dataFileContent = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        DataFile dataFile = new DataFile(testFileName, dataFileContent.getBytes());

        List<DataFile> dataFiles = buildAndDecryptToMemory(dataFile);
        assertFileDataFileContent(dataFiles.get(0), dataFile.getName(), dataFileContent.getBytes());
        closeInMemoryStreams(dataFiles);
    }

    @Test
    public void buildAndDecryptCDOC10_RSA_fromMemory_toMemory_withDDOC_shouldSucceed() throws Exception {
        String dataFileContent = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        DataFile dataFile = new DataFile("testFile1", dataFileContent.getBytes());

        String dataFileContent2 = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce felis urna, consequat vel eros vel, " +
                "ornare aliquet ante. Integer justo dolor, egestas nec mi vitae, semper consectetur odio.";
        DataFile dataFile2 = new DataFile("testFile2", dataFileContent2.getBytes());

        List<DataFile> dataFiles = buildAndDecryptToMemory(dataFile, dataFile2);
        assertFileDataFileContent(dataFiles.get(0), dataFile.getName(), dataFileContent.getBytes());
        assertFileDataFileContent(dataFiles.get(1), dataFile2.getName(), dataFileContent2.getBytes());
        closeInMemoryStreams(dataFiles);
    }

    @Test
    public void buildAndDecryptCDOC10_RSA_fromMemory_toMemory_withSingleFile_100times_shouldSucceed() throws Exception {
        for (String dataFileContent = "a"; dataFileContent.length() < 100; dataFileContent += 'a') {
            DataFile dataFile = new DataFile(testFileName, dataFileContent.getBytes());

            List<DataFile> dataFiles = buildAndDecryptToMemory(dataFile);
            assertFileDataFileContent(dataFiles.get(0), dataFile.getName(), dataFileContent.getBytes());
            closeInMemoryStreams(dataFiles);
        }
    }

    @Ignore("Needs investigation why it's failing")
    @Test
    public void buildAndDecryptCDOC10_RSA_fromMemory_toMemory_withDDOC_100times_shouldSucceed() throws Exception {
        for (String dataFileContent = "a"; dataFileContent.length() < 100; dataFileContent += 'a') {
            DataFile dataFile = new DataFile("testFile.txt", dataFileContent.getBytes());
            String dataFile2Content = "second_file_content";
            DataFile dataFile2 = mockDataFile(dataFile2Content);
            List<DataFile> dataFiles = buildAndDecryptToMemory(dataFile, dataFile2);
            assertFileDataFileContent(dataFiles.get(0), dataFile.getName(), dataFileContent.getBytes());
            assertFileDataFileContent(dataFiles.get(1), dataFile2.getName(), dataFile2Content.getBytes());
            closeInMemoryStreams(dataFiles);
        }
    }

    @Test
    public void decryptValidCDOC10_RSA_withSingleFileWithoutExtension_fileAlreadyExists_withDefaultCDOCFileSystemHandler() throws Exception {
        File initialFile = new File("target/testdata/lorem2");
        initialFile.createNewFile();
        DataFile dataFile = new DataFile("lorem2", "Lorem ipsum dolor sit amet, consectetur adipiscing elit.".getBytes());

        List<File> dataFiles = buildAndDecryptToFile(dataFile);
        assertFileDataFileContent(dataFiles.get(0), "lorem2_1", "Lorem ipsum dolor sit amet, consectetur adipiscing elit.");
        deleteTestFiles(dataFiles);
    }

    @Test
    public void buildAndDecryptCDOC10_RSA_toFile_withDDOC_shouldSucceed() throws Exception {
        String dataFileContent = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        DataFile dataFile = new DataFile("testFile1.txt", dataFileContent.getBytes());

        String dataFileContent2 = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce felis urna, consequat vel eros vel, " +
                "ornare aliquet ante. Integer justo dolor, egestas nec mi vitae, semper consectetur odio.";
        DataFile dataFile2 = new DataFile("testFile2.txt", dataFileContent2.getBytes());

        List<File> dataFiles = buildAndDecryptToFile(dataFile, dataFile2);
        assertFileDataFileContent(dataFiles.get(0), dataFile.getName(), dataFileContent);
        assertFileDataFileContent(dataFiles.get(1), dataFile2.getName(), dataFileContent2);
        deleteTestFiles(dataFiles);
    }

    @Test
    public void buildAndDecryptCDOC10_withMultipleRecipients_shouldSucceed() throws Exception {
        String dataFileContent = "test CDOC 1.0 with multiple recipients";
        DataFile dataFile = new DataFile(testFileName, dataFileContent.getBytes());

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CDOCBuilder.version(version)
                .withDataFile(dataFile)
                .withRecipient(getClass().getResourceAsStream("/rsa/auth_cert.pem"))
                .withRecipient(getClass().getResourceAsStream("/rsa/auth_cert.pem"))
                .buildToOutputStream(baos);

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        PKCS12Token token = new PKCS12Token(new FileInputStream("src/test/resources/rsa/rsa.p12"), "test");
        List<File> decryptedDataFiles = new CDOCDecrypter()
                .withToken(token)
                .withCDOC(bais)
                .decrypt(new File("target/testdata"));

        assertSame(1, decryptedDataFiles.size());
        assertFileDataFileContent(decryptedDataFiles.get(0), dataFile.getName(), dataFileContent);
        deleteTestFiles(decryptedDataFiles);
    }

    @Test
    public void buildAndDecryptCDOC10_emptyFile_shouldSucceed() throws Exception {
        File fileToWriteToCDOC = new File("src/test/resources/cdoc/empty_file.txt");
        DataFile dataFile = new DataFile(fileToWriteToCDOC);

        List<File> dataFiles = buildAndDecryptToFile(dataFile);
        assertFileDataFileContent(dataFiles.get(0), "empty_file.txt", "");

        deleteTestFiles(dataFiles);
    }

    @Test
    public void buildAndDecryptCDOC10_with95megabytesFile() throws CDOCException, IOException {
        File tempFile = File.createTempFile("bigFile", "-95megabytes");
        BufferedWriter bw = new BufferedWriter(new FileWriter(tempFile));
        for (int i = 0; i < 10000000; i++) {
            bw.write("aaaaaaaaaa");
        }
        bw.close();

        DataFile dataFile = new DataFile(tempFile);

        List<File> dataFiles = buildAndDecryptToFile(dataFile);
        assertEquals(100000000, dataFiles.get(0).length());
        tempFile.deleteOnExit();
        deleteTestFiles(dataFiles);
    }

    @Test(expected = XmlParseException.class)
    public void decryptInvalidStructureCDOC10_shouldThrowException() throws Exception {
        FileInputStream cdocInputStream = new FileInputStream("src/test/resources/cdoc/invalid_cdoc10_structure.cdoc");
        new CDOCDecrypter()
                .withToken(new PKCS12Token(new FileInputStream("src/test/resources/rsa/rsa.p12"), "test"))
                .withCDOC(cdocInputStream)
                .decrypt(new File("target/testdata"));
    }

    private List<DataFile> buildAndDecryptToMemory(DataFile... dataFiles) throws CDOCException, IOException {
        InputStream certificateInputStream = getClass().getResourceAsStream("/rsa/auth_cert.pem");

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CDOCBuilder.version(version)
                .withDataFiles(Arrays.asList(dataFiles))
                .withRecipient(certificateInputStream)
                .buildToOutputStream(baos);

        PKCS12Token token = new PKCS12Token(new FileInputStream("src/test/resources/rsa/rsa.p12"), "test");
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        List<DataFile> decryptedDataFiles = new CDOCDecrypter()
                .withToken(token)
                .withCDOC(bais)
                .decrypt();
        
        assertTrue(decryptedDataFiles.size() == dataFiles.length);
        for (DataFile dataFile : dataFiles) {
            assertStreamClosed(dataFile.getContent());
        }
        assertStreamClosed(certificateInputStream);
        return decryptedDataFiles;
    }

    private List<File> buildAndDecryptToFile(DataFile... dataFiles) throws CDOCException, IOException {
        InputStream certificateInputStream = getClass().getResourceAsStream("/rsa/auth_cert.pem");
        File CDOCDestination = new File("target/valid_10.cdoc");
        CDOCBuilder.version(version)
                .withDataFiles(Arrays.asList(dataFiles))
                .withRecipient(certificateInputStream)
                .buildToFile(CDOCDestination);

        FileInputStream rsaToken = new FileInputStream("src/test/resources/rsa/rsa.p12");
        PKCS12Token token = new PKCS12Token(rsaToken, "test");
        List<File> decryptedDataFiles = new CDOCDecrypter()
                .withToken(token)
                .withCDOC(CDOCDestination)
                .decrypt(new File("target/testdata"));

        assertTrue(decryptedDataFiles.size() == dataFiles.length);
        for (DataFile dataFile : dataFiles) {
            assertStreamClosed(dataFile.getContent());
        }
        assertStreamClosed(certificateInputStream);
        return decryptedDataFiles;
    }
}

