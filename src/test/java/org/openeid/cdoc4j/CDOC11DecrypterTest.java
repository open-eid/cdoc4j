package org.openeid.cdoc4j;

import static org.junit.Assert.assertSame;
import static org.openeid.cdoc4j.TestUtil.*;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.openeid.cdoc4j.token.pkcs11.PKCS11Token;
import org.openeid.cdoc4j.token.pkcs11.PKCS11TokenParams;
import org.openeid.cdoc4j.token.pkcs12.PKCS12Token;
import org.openeid.cdoc4j.xml.exception.XmlParseException;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class CDOC11DecrypterTest {

    private final String version = "1.1";
    private final String testFileName = "test.txt";

    @Test
    public void decryptValidCDOC11_RSA_withSingleFile_shouldSucceed() throws Exception {
        PKCS12Token token = new PKCS12Token(new FileInputStream("src/test/resources/rsa/rsa.p12"), "test");

        List<File> dataFiles = new CDOCDecrypter()
                .withToken(token)
                .withCDOC(new FileInputStream("src/test/resources/cdoc/valid_cdoc11_RSA.cdoc"))
                .decrypt(new File("target/testdata"));

        assertSame(1, dataFiles.size());
        assertFileDataFileContent(dataFiles.get(0), "lorem2.txt", "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce felis urna, consequat vel eros vel, ornare aliquet ante. Integer justo dolor, egestas nec mi vitae, semper consectetur odio. Morbi sagittis egestas leo, vel molestie ligula condimentum vitae. Aliquam porttitor in turpis ornare venenatis. Cras vel nunc quis massa tristique consectetur. Vestibulum");
        deleteTestFiles(dataFiles);
    }

    @Test
    public void decryptValidCDOC11_RSA_toMemory_withSingleFile_shouldSucceed() throws Exception {
        PKCS12Token token = new PKCS12Token(new FileInputStream("src/test/resources/rsa/rsa.p12"), "test");

        List<DataFile> dataFiles = new CDOCDecrypter()
                .withToken(token)
                .withCDOC(new FileInputStream("src/test/resources/cdoc/valid_cdoc11_RSA.cdoc"))
                .decrypt();
        assertSame(1, dataFiles.size());
        assertDataFileContent(dataFiles.get(0), "lorem2.txt", "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce felis urna, consequat vel eros vel, ornare aliquet ante. Integer justo dolor, egestas nec mi vitae, semper consectetur odio. Morbi sagittis egestas leo, vel molestie ligula condimentum vitae. Aliquam porttitor in turpis ornare venenatis. Cras vel nunc quis massa tristique consectetur. Vestibulum");
    }

    @Test
    public void decryptInvalidCDOC11_RSA_withMultipleFiles_shouldDeleteAllFiles() throws Exception {
        PKCS12Token token = new PKCS12Token(new FileInputStream("src/test/resources/rsa/rsa.p12"), "test");
        try {
            new CDOCDecrypter()
                    .withToken(token)
                    .withCDOC(new FileInputStream("src/test/resources/cdoc/invalid_cdoc11_multiple_files.cdoc"))
                    .decrypt(new File("target/testdata"));
        } catch (Exception e) {
            Assert.assertFalse(new File("target/testdata/test1.txt").exists());
        }
    }

    @Test
    public void decryptValidCDOC11_RSA_withSingleFile_fileAlreadyExists_withDefaultCDOCFileSystemHandler() throws Exception {
        PKCS12Token token = new PKCS12Token(new FileInputStream("src/test/resources/rsa/rsa.p12"), "test");
        File initialFile = new File("target/testdata/lorem2.txt");
        initialFile.createNewFile();

        List<File> dataFiles = new CDOCDecrypter()
                .withToken(token)
                .withCDOC(new FileInputStream("src/test/resources/cdoc/valid_cdoc11_RSA.cdoc"))
                .decrypt(new File("target/testdata"));

        assertFileDataFileContent(dataFiles.get(0), "lorem2_1.txt", "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce felis urna, consequat vel eros vel, ornare aliquet ante. Integer justo dolor, egestas nec mi vitae, semper consectetur odio. Morbi sagittis egestas leo, vel molestie ligula condimentum vitae. Aliquam porttitor in turpis ornare venenatis. Cras vel nunc quis massa tristique consectetur. Vestibulum");
        List<File> deletableDataFiles = new ArrayList<>();
        deletableDataFiles.add(initialFile);
        deletableDataFiles.addAll(dataFiles);
        deleteTestFiles(deletableDataFiles);
    }

    @Test
    public void decryptValidCDOC11_RSA_withSingleFile_fileAlreadyExists_withCustomCDOCFileSystemHandler() throws Exception {
        PKCS12Token token = new PKCS12Token(new FileInputStream("src/test/resources/rsa/rsa.p12"), "test");
        File initialFile = new File("target/testdata/lorem2.txt");
        initialFile.createNewFile();
        CDOCFileSystemHandler cdocFileSystemHandler = new CDOCFileSystemHandler() {
            @Override
            public File onFileExists(File existingFile) {
                existingFile.delete();
                return existingFile;
            }
        };

        List<File> dataFiles = new CDOCDecrypter()
                .withToken(token)
                .withCDOC(new FileInputStream("src/test/resources/cdoc/valid_cdoc11_RSA.cdoc"))
                .withCDOCFileSystemHandler(cdocFileSystemHandler)
                .decrypt(new File("target/testdata"));

        assertFileDataFileContent(dataFiles.get(0), "lorem2.txt", "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce felis urna, consequat vel eros vel, ornare aliquet ante. Integer justo dolor, egestas nec mi vitae, semper consectetur odio. Morbi sagittis egestas leo, vel molestie ligula condimentum vitae. Aliquam porttitor in turpis ornare venenatis. Cras vel nunc quis massa tristique consectetur. Vestibulum");
        List<File> deletableDataFiles = new ArrayList<>();
        deletableDataFiles.add(initialFile);
        deletableDataFiles.addAll(dataFiles);
        deleteTestFiles(deletableDataFiles);

    }

    @Test
    public void decryptValidCDOC11_RSA_withDDOCContaining2Files_shouldSucceed() throws Exception {
        PKCS12Token token = new PKCS12Token(new FileInputStream("src/test/resources/rsa/rsa.p12"), "test");

        List<File> dataFiles = new CDOCDecrypter()
                .withToken(token)
                .withCDOC(new FileInputStream("src/test/resources/cdoc/valid_cdoc11_RSA_withDDOC.cdoc"))
                .decrypt(new File("target/testdata"));

        assertSame(2, dataFiles.size());
        assertFileDataFileContent(dataFiles.get(0), "lorem1.txt", "lorem ipsum");
        assertFileDataFileContent(dataFiles.get(1), "lorem2.txt", "Lorem ipsum dolor sit amet");
        deleteTestFiles(dataFiles);
    }

    @Test
    public void decryptValidCDOC11_RSA_withDataFileResponse_withDDOCContaining2Files_shouldSucceed() throws Exception {
        PKCS12Token token = new PKCS12Token(new FileInputStream("src/test/resources/rsa/rsa.p12"), "test");

        List<DataFile> dataFiles = new CDOCDecrypter()
                .withToken(token)
                .withCDOC(new FileInputStream("src/test/resources/cdoc/valid_cdoc11_RSA_withDDOC.cdoc"))
                .decrypt();
        assertSame(2, dataFiles.size());
        assertDataFileContent(dataFiles.get(0), "lorem1.txt", "lorem ipsum");
        assertDataFileContent(dataFiles.get(1), "lorem2.txt", "Lorem ipsum dolor sit amet");
    }

    @Test
    public void decryptValidCDOC11_RSA_withDDOCContaining2Files_filesAlreadyExist_withDefaultCDOCFileSystemHandler() throws Exception {
        PKCS12Token token = new PKCS12Token(new FileInputStream("src/test/resources/rsa/rsa.p12"), "test");
        File initialFile = new File("target/testdata/lorem1.txt");
        File initialFile2 = new File("target/testdata/lorem2.txt");
        File initialFile3 = new File("target/testdata/lorem2_1.txt");
        initialFile.createNewFile();
        initialFile2.createNewFile();
        initialFile3.createNewFile();
        List<File> dataFiles = new CDOCDecrypter()
                .withToken(token)
                .withCDOC(new FileInputStream("src/test/resources/cdoc/valid_cdoc11_RSA_withDDOC.cdoc"))
                .decrypt(new File("target/testdata"));

        assertFileDataFileContent(dataFiles.get(0), "lorem1_1.txt", "lorem ipsum");
        assertFileDataFileContent(dataFiles.get(1), "lorem2_2.txt", "Lorem ipsum dolor sit amet");
        List<File> deletableDataFiles = new ArrayList<>();
        deletableDataFiles.add(initialFile);
        deletableDataFiles.add(initialFile2);
        deletableDataFiles.add(initialFile3);
        deletableDataFiles.addAll(dataFiles);
        deleteTestFiles(deletableDataFiles);
    }

    @Test
    public void decryptValidCDOC11_ECC_withSingleFile_shouldSucceed() throws Exception {
        PKCS12Token token = new PKCS12Token(new FileInputStream("src/test/resources/ecc/ecc.p12"), "test");

        List<File> dataFiles = new CDOCDecrypter()
                .withToken(token)
                .withCDOC(new FileInputStream("src/test/resources/cdoc/valid_cdoc11_ECC.cdoc"))
                .decrypt(new File("target/testdata"));

        assertSame(1, dataFiles.size());
        assertFileDataFileContent(dataFiles.get(0), "lorem1.txt", "lorem ipsum");
        deleteTestFiles(dataFiles);
    }

    @Test
    public void decryptValidCDOC11_ECC_withDataFileResponse_withSingleFile_shouldSucceed() throws Exception {
        PKCS12Token token = new PKCS12Token(new FileInputStream("src/test/resources/ecc/ecc.p12"), "test");

        List<DataFile> dataFiles = new CDOCDecrypter()
                .withToken(token)
                .withCDOC(new FileInputStream("src/test/resources/cdoc/valid_cdoc11_ECC.cdoc"))
                .decrypt();

        assertSame(1, dataFiles.size());
        assertDataFileContent(dataFiles.get(0), "lorem1.txt", "lorem ipsum");
    }

    @Test
    public void decryptValidCDOC11_ECC_withDDOCContaining2Files_shouldSucceed() throws Exception {
        PKCS12Token token = new PKCS12Token(new FileInputStream("src/test/resources/ecc/ecc.p12"), "test");

        List<File> dataFiles = new CDOCDecrypter()
                .withToken(token)
                .withCDOC(new FileInputStream("src/test/resources/cdoc/valid_cdoc11_ECC_withDDOC.cdoc"))
                .decrypt(new File("target/testdata"));

        assertSame(2, dataFiles.size());
        assertFileDataFileContent(dataFiles.get(0), "lorem1.txt", "lorem ipsum");
        assertFileDataFileContent(dataFiles.get(1), "lorem2.txt", "Lorem ipsum dolor sit amet");
        deleteTestFiles(dataFiles);
    }

    @Test
    public void buildAndDecryptCDOC11_RSA_toFile_withSingleFile_shouldSucceed() throws Exception {
        String dataFileContent = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        DataFile dataFile = new DataFile(testFileName, dataFileContent.getBytes(StandardCharsets.UTF_8));
        InputStream certificateInputStream = getClass().getResourceAsStream("/rsa/auth_cert.pem");

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CDOCBuilder.version(version)
                .withDataFile(dataFile)
                .withRecipient(certificateInputStream)
                .buildToOutputStream(baos);

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        PKCS12Token token = new PKCS12Token(new FileInputStream("src/test/resources/rsa/rsa.p12"), "test");
        List<File> decryptedDataFiles = new CDOCDecrypter()
                .withToken(token)
                .withCDOC(bais)
                .decrypt(new File("target/testdata"));

        assertSame(1, decryptedDataFiles.size());
        assertFileDataFileContent(decryptedDataFiles.get(0), dataFile.getName(), dataFileContent);

        assertStreamClosed(dataFile.getContent());
        assertStreamClosed(certificateInputStream);

        deleteTestFiles(decryptedDataFiles);
    }

    @Test
    public void buildAndDecryptCDOC11_RSA_fromMemory_toMemory_withSingleFile_100times_shouldSucceed() throws Exception {
        for (String dataFileContent = ""; dataFileContent.length() < 100; dataFileContent += 'a') {
            DataFile dataFile = new DataFile(testFileName, dataFileContent.getBytes(StandardCharsets.UTF_8));
            InputStream certificateInputStream = getClass().getResourceAsStream("/rsa/auth_cert.pem");

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            CDOCBuilder.version(version)
                    .withDataFile(dataFile)
                    .withRecipient(certificateInputStream)
                    .buildToOutputStream(baos);

            ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
            PKCS12Token token = new PKCS12Token(new FileInputStream("src/test/resources/rsa/rsa.p12"), "test");
            List<DataFile> decryptedDataFiles = new CDOCDecrypter()
                    .withToken(token)
                    .withCDOC(bais)
                    .decrypt();

            assertSame(1, decryptedDataFiles.size());
            assertFileDataFileContent(decryptedDataFiles.get(0), dataFile.getName(), dataFileContent.getBytes());

            assertStreamClosed(dataFile.getContent());
            assertStreamClosed(certificateInputStream);
            assertStreamClosed(bais);
            closeInMemoryStreams(decryptedDataFiles);
        }
    }

    @Test
    public void buildAndDecryptCDOC11_RSA_withDDOC_100times_shouldSucceed() throws Exception {
        for (String dataFileContent = ""; dataFileContent.length() < 100; dataFileContent += 'a') {
            DataFile dataFile = new DataFile(testFileName, dataFileContent.getBytes(StandardCharsets.UTF_8));
            InputStream certificateInputStream = getClass().getResourceAsStream("/rsa/auth_cert.pem");

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataFile smallFile = mockDataFile("small_file");
            CDOCBuilder.version(version)
                    .withDataFile(dataFile)
                    .withDataFile(smallFile)
                    .withRecipient(certificateInputStream)
                    .buildToOutputStream(baos);

            ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
            PKCS12Token token = new PKCS12Token(new FileInputStream("src/test/resources/rsa/rsa.p12"), "test");
            List<DataFile> decryptedDataFiles = new CDOCDecrypter()
                    .withToken(token)
                    .withCDOC(bais)
                    .decrypt();

            assertSame(2, decryptedDataFiles.size());
            assertFileDataFileContent(decryptedDataFiles.get(0), dataFile.getName(), dataFileContent.getBytes());
            assertFileDataFileContent(decryptedDataFiles.get(1), smallFile.getName(), "small_file".getBytes());

            assertStreamClosed(dataFile.getContent());
            assertStreamClosed(certificateInputStream);
            closeInMemoryStreams(decryptedDataFiles);
        }
    }

    @Test
    public void buildAndDecryptCDOC11_EC_withSingleFile_shouldSucceed() throws Exception {
        String dataFileContent = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        DataFile dataFile = new DataFile(testFileName, dataFileContent.getBytes(StandardCharsets.UTF_8));
        InputStream certificateInputStream = getClass().getResourceAsStream("/ecc/auth_cert.pem");

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CDOCBuilder.version(version)
                .withDataFile(dataFile)
                .withRecipient(certificateInputStream)
                .buildToOutputStream(baos);

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        PKCS12Token token = new PKCS12Token(new FileInputStream("src/test/resources/ecc/ecc.p12"), "test");
        List<File> decryptedDataFiles = new CDOCDecrypter()
                .withToken(token)
                .withCDOC(bais)
                .decrypt(new File("target/testdata"));

        assertSame(1, decryptedDataFiles.size());
        assertFileDataFileContent(decryptedDataFiles.get(0), dataFile.getName(), dataFileContent);

        assertStreamClosed(dataFile.getContent());
        assertStreamClosed(certificateInputStream);

        deleteTestFiles(decryptedDataFiles);
    }

    @Test
    public void buildAndDecryptCDOC11_EC_fromMemory_toMemory_withDDOC_shouldSucceed() throws Exception {
        String dataFileContent = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        DataFile dataFile = new DataFile(testFileName, dataFileContent.getBytes(StandardCharsets.UTF_8));
        String dataFileContent2 = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        DataFile dataFile2 = new DataFile(testFileName, dataFileContent.getBytes(StandardCharsets.UTF_8));

        InputStream certificateInputStream = getClass().getResourceAsStream("/ecc/auth_cert.pem");

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CDOCBuilder.version(version)
                .withDataFile(dataFile)
                .withDataFile(dataFile2)
                .withRecipient(certificateInputStream)
                .buildToOutputStream(baos);

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        PKCS12Token token = new PKCS12Token(new FileInputStream("src/test/resources/ecc/ecc.p12"), "test");
        List<DataFile> decryptedDataFiles = new CDOCDecrypter()
                .withToken(token)
                .withCDOC(bais)
                .decrypt();

        assertSame(2, decryptedDataFiles.size());
        assertFileDataFileContent(decryptedDataFiles.get(0), dataFile.getName(), dataFileContent.getBytes());
        assertFileDataFileContent(decryptedDataFiles.get(1), dataFile2.getName() , dataFileContent2.getBytes());

        assertStreamClosed(dataFile.getContent());
        assertStreamClosed(dataFile2.getContent());
        assertStreamClosed(certificateInputStream);
        closeInMemoryStreams(decryptedDataFiles);
    }

    @Test
    public void buildAndDecryptCDOC11_withMultipleRecipients_shouldSucceed() throws Exception {
        String dataFileContent = "test CDOC 1.1 with multiple recipients";
        DataFile dataFile = new DataFile(testFileName, dataFileContent.getBytes(StandardCharsets.UTF_8));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CDOCBuilder.version(version)
                .withDataFile(dataFile)
                .withRecipient(getClass().getResourceAsStream("/ecc/auth_cert.pem"))
                .withRecipient(getClass().getResourceAsStream("/rsa/auth_cert.pem"))
                .buildToOutputStream(baos);

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        PKCS12Token token = new PKCS12Token(new FileInputStream("src/test/resources/ecc/ecc.p12"), "test");
        List<DataFile> decryptedDataFiles = new CDOCDecrypter()
                .withToken(token)
                .withCDOC(bais)
                .decrypt();

        assertSame(1, decryptedDataFiles.size());
        assertFileDataFileContent(decryptedDataFiles.get(0), dataFile.getName(), dataFileContent.getBytes());
        closeInMemoryStreams(decryptedDataFiles);
    }

    @Test(expected = XmlParseException.class)
    public void decryptCDOC11_withEntityExpansionAttack_shouldThrowException() throws Exception {
        InputStream cdocInputStream = getClass().getResourceAsStream("/cdoc/1.0-XXE.cdoc");

        PKCS12Token token = new PKCS12Token(new FileInputStream("src/test/resources/rsa/rsa.p12"), "test");
        new CDOCDecrypter()
                .withToken(token)
                .withCDOC(cdocInputStream)
                .decrypt(new File("target/testdata"));

    }

    @Test
    public void buildAndDecryptCDOC11_emptyFile_shouldSucceed() throws Exception {
        File fileToWriteToCDOC = new File("src/test/resources/cdoc/empty_file.txt");
        DataFile dataFile = new DataFile(fileToWriteToCDOC);

        InputStream certificateInputStream = getClass().getResourceAsStream("/ecc/auth_cert.pem");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CDOCBuilder.version(version)
                .withDataFile(dataFile)
                .withRecipient(certificateInputStream)
                .buildToOutputStream(baos);

        PKCS12Token token = new PKCS12Token(new FileInputStream("src/test/resources/ecc/ecc.p12"), "test");
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        List<File> dataFiles = new CDOCDecrypter()
                .withToken(token)
                .withCDOC(bais)
                .decrypt(new File("target/testdata"));
        assertFileDataFileContent(dataFiles.get(0), "empty_file.txt", "");

        deleteTestFiles(dataFiles);
    }

    @Test(expected = XmlParseException.class)
    public void decryptInvalidStructureCDOC11_shouldThrowException() throws Exception {
        FileInputStream cdocInputStream = new FileInputStream("src/test/resources/cdoc/invalid_cdoc11_structure.cdoc");
        new CDOCDecrypter()
                .withToken(new PKCS12Token(new FileInputStream("src/test/resources/rsa/rsa.p12"), "test"))
                .withCDOC(cdocInputStream)
                .decrypt(new File("target/testdata"));
    }

    @Ignore("Requires SmartCard with its Reader to be connected to the machine")
    @Test
    public void buildAndDecryptCDOC_withPKCS11_shouldSucceed() throws Exception {
        String fileContent = "test CDOC 1.1 with PKCS#11";
        DataFile dataFile = new DataFile("test.txt", fileContent.getBytes());

        InputStream certificateInputStream = getClass().getResourceAsStream("/path/to/cert"); // set desired certificate
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CDOCBuilder.version("1.1")
                .withDataFile(dataFile)
                .withRecipient(certificateInputStream)
                .buildToOutputStream(baos);

        PKCS11TokenParams params = new PKCS11TokenParams("/usr/local/lib/onepin-opensc-pkcs11.so", "DO NOT COMMIT YOUR PIN!".toCharArray(), 0);
        PKCS11Token token = new PKCS11Token(params);
        List<File> dataFiles = new CDOCDecrypter()
                .withToken(token)
                .withCDOC(new ByteArrayInputStream(baos.toByteArray()))
                .decrypt(new File("target/testdata"));

        assertFileDataFileContent(dataFiles.get(0), dataFile.getName(), fileContent);

        deleteTestFiles(dataFiles);
    }

}
