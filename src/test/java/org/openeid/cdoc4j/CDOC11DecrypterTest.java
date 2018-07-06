package org.openeid.cdoc4j;

import org.junit.Ignore;
import org.junit.Test;
import org.openeid.cdoc4j.token.pkcs11.PKCS11Token;
import org.openeid.cdoc4j.token.pkcs11.PKCS11TokenParams;
import org.openeid.cdoc4j.token.pkcs12.PKCS12Token;
import org.openeid.cdoc4j.xml.exception.XmlParseException;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.Assert.assertSame;
import static org.openeid.cdoc4j.TestUtil.*;

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
        deleteTestFile(dataFiles);
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
        deleteTestFile(dataFiles);
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
        deleteTestFile(dataFiles);
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
        deleteTestFile(dataFiles);
    }

    @Test
    public void buildAndDecryptCDOC11_RSA_fromMemory_toMemory_withSingleFile_shouldSucceed() throws Exception {
        String dataFileContent = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        DataFile dataFile = new DataFile(testFileName, new ByteArrayInputStream(dataFileContent.getBytes(StandardCharsets.UTF_8)));
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

        deleteTestFile(decryptedDataFiles);
    }

    @Test
    public void buildAndDecryptCDOC11_RSA_fromMemory_toMemory_withSingleFile_100times_shouldSucceed() throws Exception {
        for (String dataFileContent = ""; dataFileContent.length() < 100; dataFileContent += 'a') {
            DataFile dataFile = new DataFile(testFileName, new ByteArrayInputStream(dataFileContent.getBytes(StandardCharsets.UTF_8)));
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
            assertStreamClosed(bais);

            deleteTestFile(decryptedDataFiles);
        }
    }

    @Test
    public void buildAndDecryptCDOC11_RSA_fromMemory_toMemory_withDDOC_100times_shouldSucceed() throws Exception {
        for (String dataFileContent = ""; dataFileContent.length() < 100; dataFileContent += 'a') {
            DataFile dataFile = new DataFile(testFileName, new ByteArrayInputStream(dataFileContent.getBytes(StandardCharsets.UTF_8)));
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
            List<File> decryptedDataFiles = new CDOCDecrypter()
                    .withToken(token)
                    .withCDOC(bais)
                    .decrypt(new File("target/testdata"));

            assertSame(2, decryptedDataFiles.size());
            assertFileDataFileContent(decryptedDataFiles.get(0), dataFile.getName(), dataFileContent);
            assertFileDataFileContent(decryptedDataFiles.get(1), smallFile.getName(), "small_file");

            assertStreamClosed(dataFile.getContent());
            assertStreamClosed(certificateInputStream);

            deleteTestFile(decryptedDataFiles);
        }
    }

    @Test
    public void buildAndDecryptCDOC11_EC_fromMemory_toMemory_withSingleFile_shouldSucceed() throws Exception {
        String dataFileContent = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        DataFile dataFile = new DataFile(testFileName, new ByteArrayInputStream(dataFileContent.getBytes(StandardCharsets.UTF_8)));
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

        deleteTestFile(decryptedDataFiles);
    }

    @Test
    public void buildAndDecryptCDOC11_EC_fromMemory_toMemory_withDDOC_shouldSucceed() throws Exception {
        String dataFileContent = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        DataFile dataFile = new DataFile(testFileName, new ByteArrayInputStream(dataFileContent.getBytes(StandardCharsets.UTF_8)));
        String dataFileContent2 = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        DataFile dataFile2 = new DataFile(testFileName, new ByteArrayInputStream(dataFileContent.getBytes(StandardCharsets.UTF_8)));

        InputStream certificateInputStream = getClass().getResourceAsStream("/ecc/auth_cert.pem");

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CDOCBuilder.version(version)
                .withDataFile(dataFile)
                .withDataFile(dataFile2)
                .withRecipient(certificateInputStream)
                .buildToOutputStream(baos);

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        PKCS12Token token = new PKCS12Token(new FileInputStream("src/test/resources/ecc/ecc.p12"), "test");
        List<File> decryptedDataFiles = new CDOCDecrypter()
                .withToken(token)
                .withCDOC(bais)
                .decrypt(new File("target/testdata"));

        assertSame(2, decryptedDataFiles.size());
        assertFileDataFileContent(decryptedDataFiles.get(0), dataFile.getName(), dataFileContent);
        assertFileDataFileContent(decryptedDataFiles.get(1), dataFile2.getName(), dataFileContent2);

        assertStreamClosed(dataFile.getContent());
        assertStreamClosed(dataFile2.getContent());
        assertStreamClosed(certificateInputStream);
        deleteTestFile(decryptedDataFiles);
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
        List<File> decryptedDataFiles = new CDOCDecrypter()
                .withToken(token)
                .withCDOC(bais)
                .decrypt(new File("target/testdata"));

        assertSame(1, decryptedDataFiles.size());
        assertFileDataFileContent(decryptedDataFiles.get(0), dataFile.getName(), dataFileContent.getBytes());

        deleteTestFile(decryptedDataFiles);
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
        List<File> dataFiles =  new CDOCDecrypter()
                .withToken(token)
                .withCDOC(bais)
                .decrypt(new File("target/testdata"));
        assertFileDataFileContent(dataFiles.get(0), "empty_file.txt", "");

        deleteTestFile(dataFiles);
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

        deleteTestFile(dataFiles);
    }

}
