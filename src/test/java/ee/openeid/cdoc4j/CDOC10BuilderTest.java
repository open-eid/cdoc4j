package ee.openeid.cdoc4j;

import ee.openeid.cdoc4j.exception.CDOCException;
import ee.openeid.cdoc4j.exception.DataFileMissingException;
import ee.openeid.cdoc4j.exception.RecipientCertificateException;
import ee.openeid.cdoc4j.exception.RecipientMissingException;
import org.junit.Test;

import java.io.InputStream;

public class CDOC10BuilderTest {

    @Test(expected = RecipientMissingException.class)
    public void buildCDOC10_withoutRecipient_shouldThrowException() throws CDOCException {
        DataFile dataFile = new DataFile("test.txt", "test".getBytes());
        CDOCBuilder.version("1.0")
                .withDataFile(dataFile).build();
    }

    @Test(expected = DataFileMissingException.class)
    public void buildCDOC10_withoutDataFile_shouldThrowException() throws CDOCException {
        InputStream certificateInputStream = CDOC10BuilderTest.class.getResourceAsStream("/rsa/auth_cert.pem");
        CDOCBuilder.version("1.0")
                .withRecipient(certificateInputStream)
                .build();
    }

    @Test(expected = RecipientCertificateException.class)
    public void buildCDOC10_withRecipientCertificateMissingKeyEnciphermentKeyUsage_shouldThrowException() throws CDOCException {
        DataFile dataFile = new DataFile("test.txt", "test".getBytes());
        InputStream certificateInputStream = CDOC10BuilderTest.class.getResourceAsStream("/rsa/sign_cert.pem");
        CDOCBuilder.version("1.0")
                .withDataFile(dataFile)
                .withRecipient(certificateInputStream)
                .build();
    }

    @Test(expected = RecipientCertificateException.class)
    public void buildCDOC10_withECCertificate_shouldThrowException() throws CDOCException {
        DataFile dataFile = new DataFile("test.txt", "test".getBytes());
        InputStream certificateInputStream = CDOC10BuilderTest.class.getResourceAsStream("/ecc/auth_cert.pem");
        CDOCBuilder.version("1.0")
                .withDataFile(dataFile)
                .withRecipient(certificateInputStream)
                .build();
    }

    @Test
    public void buildCDOC10_withRSACertificate_shouldSucceed() throws CDOCException {
        DataFile dataFile = new DataFile("test.txt", "test".getBytes());
        InputStream certificateInputStream = CDOC10BuilderTest.class.getResourceAsStream("/rsa/auth_cert.pem");
        CDOCBuilder.version("1.0")
                .withDataFile(dataFile)
                .withRecipient(certificateInputStream)
                .build();
    }

} 
