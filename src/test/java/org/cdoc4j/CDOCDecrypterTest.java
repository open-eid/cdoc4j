package org.cdoc4j;

import org.cdoc4j.xml.exception.XmlParseException;
import org.junit.Ignore;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class CDOCDecrypterTest {

    @Test
    public void buildAndDecryptCDOC10_shouldSucceed() throws Exception {
        DataFile dataFile = new DataFile("test.txt", "test CDOC 1.0".getBytes());
        InputStream certificateInputStream = CDOC10BuilderTest.class.getResourceAsStream("/rsa/auth_cert.pem");

        byte[] cdoc = CDOCBuilder.version("1.0")
                .withDataFile(dataFile)
                .withRecipient(certificateInputStream)
                .build();

        List<DataFile> dataFiles = new CDOCDecrypter()
                .withPrivateKey(CDOC10BuilderTest.class.getResourceAsStream("/rsa/auth_priv_key.pem"))
                .decrypt(new ByteArrayInputStream(cdoc));

        assertEquals(dataFile.getFileName(), dataFiles.get(0).getFileName());
        assertArrayEquals(dataFile.getContent(), dataFiles.get(0).getContent());
    }

    @Test
    public void buildAndDecryptCDOC10_withMultipleDataFiles_shouldSucceed() throws Exception {
        DataFile dataFile = new DataFile("test.txt", "test CDOC 1.0".getBytes());
        DataFile dataFile2 = new DataFile("test2.txt", "test CDOC 1.0 vol. 2".getBytes());

        InputStream certificateInputStream = CDOC10BuilderTest.class.getResourceAsStream("/rsa/auth_cert.pem");
        byte[] cdoc = CDOCBuilder.version("1.0")
                .withDataFile(dataFile)
                .withDataFile(dataFile2)
                .withRecipient(certificateInputStream)
                .build();

        List<DataFile> dataFiles = new CDOCDecrypter()
                .withPrivateKey(CDOC10BuilderTest.class.getResourceAsStream("/rsa/auth_priv_key.pem"))
                .decrypt(new ByteArrayInputStream(cdoc));

        assertEquals(dataFile.getFileName(), dataFiles.get(0).getFileName());
        assertArrayEquals(dataFile.getContent(), dataFiles.get(0).getContent());

        assertEquals(dataFile2.getFileName(), dataFiles.get(1).getFileName());
        assertArrayEquals(dataFile2.getContent(), dataFiles.get(1).getContent());
    }

    @Test
    public void buildAndDecryptCDOC11_shouldSucceed() throws Exception {
        DataFile dataFile = new DataFile("test.txt", "test CDOC 1.1".getBytes());

        InputStream certificateInputStream = CDOC10BuilderTest.class.getResourceAsStream("/rsa/auth_cert.pem");
        byte[] cdoc = CDOCBuilder.version("1.1")
                .withDataFile(dataFile)
                .withRecipient(certificateInputStream)
                .build();

        List<DataFile> dataFiles = new CDOCDecrypter()
                .withPrivateKey(CDOC10BuilderTest.class.getResourceAsStream("/rsa/auth_priv_key.pem"))
                .decrypt(new ByteArrayInputStream(cdoc));

        assertEquals(dataFile.getFileName(), dataFiles.get(0).getFileName());
        assertArrayEquals(dataFile.getContent(), dataFiles.get(0).getContent());
    }

    @Test
    public void buildAndDecryptCDOC11_withMultipleDataFiles_shouldSucceed() throws Exception {
        DataFile dataFile = new DataFile("test.txt", "test CDOC 1.1".getBytes());
        DataFile dataFile2 = new DataFile("test2.txt", "test CDOC 1.1 vol. 2".getBytes());

        InputStream certificateInputStream = CDOC10BuilderTest.class.getResourceAsStream("/rsa/auth_cert.pem");
        byte[] cdoc = CDOCBuilder.version("1.1")
                .withDataFile(dataFile)
                .withDataFile(dataFile2)
                .withRecipient(certificateInputStream)
                .build();

        List<DataFile> dataFiles = new CDOCDecrypter()
                .withPrivateKey(CDOC10BuilderTest.class.getResourceAsStream("/rsa/auth_priv_key.pem"))
                .decrypt(new ByteArrayInputStream(cdoc));

        assertEquals(dataFile.getFileName(), dataFiles.get(0).getFileName());
        assertArrayEquals(dataFile.getContent(), dataFiles.get(0).getContent());

        assertEquals(dataFile2.getFileName(), dataFiles.get(1).getFileName());
        assertArrayEquals(dataFile2.getContent(), dataFiles.get(1).getContent());
    }

    @Test
    public void buildAndDecryptCDOC11_withECKeys_shouldSucceed() throws Exception {
        DataFile dataFile = new DataFile("test.txt", "test CDOC 1.1 with EC keys ".getBytes());

        InputStream certificateInputStream = CDOC10BuilderTest.class.getResourceAsStream("/ecc/auth_cert.pem");
        byte[] cdoc = CDOCBuilder.version("1.1")
                .withDataFile(dataFile)
                .withRecipient(certificateInputStream)
                .build();

        List<DataFile> dataFiles = new CDOCDecrypter()
                .withPrivateKey(CDOC10BuilderTest.class.getResourceAsStream("/ecc/auth_priv_key.pem"))
                .decrypt(new ByteArrayInputStream(cdoc));

        assertEquals(dataFile.getFileName(), dataFiles.get(0).getFileName());
        assertArrayEquals(dataFile.getContent(), dataFiles.get(0).getContent());
    }

    @Test
    public void buildAndDecryptCDOC11_withMultipleRecipients_shouldSucceed() throws Exception {
        DataFile dataFile = new DataFile("test.txt", "test CDOC 1.1 with multiple recipients".getBytes());

        byte[] cdoc = CDOCBuilder.version("1.1")
                .withDataFile(dataFile)
                .withRecipient(CDOC10BuilderTest.class.getResourceAsStream("/rsa/auth_cert.pem"))
                .withRecipient(CDOC10BuilderTest.class.getResourceAsStream("/ecc/auth_cert.pem"))
                .build();

        List<DataFile> dataFiles = new CDOCDecrypter()
                .asRecipient(CDOC10BuilderTest.class.getResourceAsStream("/ecc/auth_cert.pem"))
                .withPrivateKey(CDOC10BuilderTest.class.getResourceAsStream("/ecc/auth_priv_key.pem"))
                .decrypt(new ByteArrayInputStream(cdoc));

        assertEquals(dataFile.getFileName(), dataFiles.get(0).getFileName());
        assertArrayEquals(dataFile.getContent(), dataFiles.get(0).getContent());
    }

    @Test
    public void buildAndDecryptCDOC11_withECKeysAndMultipleDataFiles_shouldSucceed() throws Exception {
        List<DataFile> dataFiles = new ArrayList<>();
        dataFiles.add(new DataFile("test.txt", "test CDOC 1.1 with EC keys ".getBytes()));
        dataFiles.add(new DataFile("test2.txt", "test CDOC 1.1 vol. 2".getBytes()));

        InputStream certificateInputStream = CDOC10BuilderTest.class.getResourceAsStream("/ecc/auth_cert.pem");
        byte[] cdoc = CDOCBuilder.version("1.1")
                .withDataFiles(dataFiles)
                .withRecipient(certificateInputStream)
                .build();

        List<DataFile> decryptedDataFiles = new CDOCDecrypter()
                .withPrivateKey(CDOC10BuilderTest.class.getResourceAsStream("/ecc/auth_priv_key.pem"))
                .decrypt(new ByteArrayInputStream(cdoc));

        assertEquals(dataFiles.get(0).getFileName(), decryptedDataFiles.get(0).getFileName());
        assertArrayEquals(dataFiles.get(0).getContent(), decryptedDataFiles.get(0).getContent());

        assertEquals(dataFiles.get(1).getFileName(), decryptedDataFiles.get(1).getFileName());
        assertArrayEquals(dataFiles.get(1).getContent(), decryptedDataFiles.get(1).getContent());
    }

    @Test(expected = XmlParseException.class)
    public void decryptCDOC11_withEntityExpansionAttack_shouldThrowException() throws Exception {
        InputStream cdocInputStream = CDOC10BuilderTest.class.getResourceAsStream("/cdoc/1.0-XXE.cdoc");

        new CDOCDecrypter()
                .withPrivateKey(CDOC10BuilderTest.class.getResourceAsStream("/rsa/auth_priv_key.pem"))
                .decrypt(cdocInputStream);
    }

    @Ignore("Requires SmartCard with its Reader to be connected to the machine")
    @Test
    public void buildAndDecryptCDOC_withPKCS11_shouldSucceed() throws Exception {
        DataFile dataFile = new DataFile("test.txt", "test CDOC 1.1 with PKCS#11".getBytes());

        InputStream certificateInputStream = null; // set desired certificate
        byte[] cdoc = CDOCBuilder.version("1.1")
                .withDataFile(dataFile)
                .withRecipient(certificateInputStream)
                .build();

        List<DataFile> dataFiles = new CDOCDecrypter()
                .withPkcs11("/usr/local/lib/onepin-opensc-pkcs11.so", "DO NOT COMMIT YOUR PIN!", 0)
                .decrypt(new ByteArrayInputStream(cdoc));

        assertEquals(dataFile.getFileName(), dataFiles.get(0).getFileName());
        assertArrayEquals(dataFile.getContent(), dataFiles.get(0).getContent());
    }

}

