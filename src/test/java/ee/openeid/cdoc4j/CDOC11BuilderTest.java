package ee.openeid.cdoc4j;

import ee.openeid.cdoc4j.exception.CDOCException;
import ee.openeid.cdoc4j.exception.DataFileMissingException;
import ee.openeid.cdoc4j.exception.RecipientCertificateException;
import ee.openeid.cdoc4j.exception.RecipientMissingException;
import org.junit.Test;

import java.io.InputStream;

public class CDOC11BuilderTest {

    @Test(expected = RecipientMissingException.class)
    public void buildCDOC11_withoutRecipient_shouldThrowException() throws CDOCException {
        DataFile dataFile = new DataFile("test.txt", "test".getBytes());
        CDOCBuilder.version("1.1")
                .withDataFile(dataFile).build();
    }

    @Test(expected = DataFileMissingException.class)
    public void buildCDOC11_withoutDataFile_shouldThrowException() throws CDOCException {
        InputStream certificateInputStream = CDOC10BuilderTest.class.getResourceAsStream("/rsa/auth_cert.pem");
        CDOCBuilder.version("1.1")
                .withRecipient(certificateInputStream)
                .build();
    }

    @Test(expected = RecipientCertificateException.class)
    public void buildCDOC11_withRecipientCertificateMissingKeyEnciphermentKeyUsage_shouldThrowException() throws CDOCException {
        DataFile dataFile = new DataFile("test.txt", "test".getBytes());
        InputStream certificateInputStream = CDOC10BuilderTest.class.getResourceAsStream("/rsa/sign_cert.pem");
        CDOCBuilder.version("1.1")
                .withDataFile(dataFile)
                .withRecipient(certificateInputStream)
                .build();
    }

    @Test(expected = RecipientCertificateException.class)
    public void buildCDOC11_withRecipientECCertificateMissingKeyAgreementKeyUsage_shouldThrowException() throws CDOCException {
        DataFile dataFile = new DataFile("test.txt", "test".getBytes());
        InputStream certificateInputStream = CDOC10BuilderTest.class.getResourceAsStream("/ecc/sign_cert.pem");
        CDOCBuilder.version("1.1")
                .withDataFile(dataFile)
                .withRecipient(certificateInputStream)
                .build();
    }

    @Test
    public void buildCDOC11_withECCertificate_shouldSucceed() throws CDOCException {
        DataFile dataFile = new DataFile("test.txt", "test".getBytes());
        InputStream certificateInputStream = CDOC10BuilderTest.class.getResourceAsStream("/ecc/auth_cert.pem");
        CDOCBuilder.version("1.1")
                .withDataFile(dataFile)
                .withRecipient(certificateInputStream)
                .build();
    }

    @Test
    public void buildCDOC11_withRSACertificate_shouldSucceed() throws CDOCException {
        DataFile dataFile = new DataFile("test.txt", "test".getBytes());
        InputStream certificateInputStream = CDOC10BuilderTest.class.getResourceAsStream("/rsa/auth_cert.pem");
        CDOCBuilder.version("1.1")
                .withDataFile(dataFile)
                .withRecipient(certificateInputStream)
                .build();
    }

} 
