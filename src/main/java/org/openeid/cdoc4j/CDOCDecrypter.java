package org.openeid.cdoc4j;

import com.ctc.wstx.stax.WstxInputFactory;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openeid.cdoc4j.exception.CDOCException;
import org.openeid.cdoc4j.exception.DecryptionException;
import org.openeid.cdoc4j.exception.RecipientCertificateException;
import org.openeid.cdoc4j.exception.RecipientMissingException;
import org.openeid.cdoc4j.token.Token;
import org.openeid.cdoc4j.xml.XmlEncParser;
import org.openeid.cdoc4j.xml.XmlEncParserFactory;
import org.openeid.cdoc4j.xml.XmlEncParserUtil;
import org.openeid.cdoc4j.xml.exception.XmlParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import java.io.*;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.ArrayList;
import java.util.List;

/**
 * Class for decrypting CDOC documents (supports 1.0 and 1.1)
 * <p>
 *   <b>Example of decrypting CDOC document with PKCS#11:</b>
 * </p>
 * <p><code>
 *   PKCS11TokenParams params = new PKCS11TokenParams("/path/to/pkcs11/driver", "your PIN1", 0);
 *   PKCS11Token token = new PKCS11Token(params) <br/>
 *   List<File> dataFiles = new CDOCDecrypter() <br/>
 *   &nbsp;&nbsp;.withToken(token) <br/>
 *   &nbsp;&nbsp;.withCDOC(new File("/path/to/cdoc")) <br/>
 *   &nbsp;&nbsp;.withCDOCFileSystemHandler(new CustomCDOCFileSystemHandler()) <br/>
 *   &nbsp;&nbsp;.decrypt(new File("path/to/target/directory")); <br/>
 * </code></p>
 * <p>
 *   <b>Example of decrypting CDOC document with PKCS#12:</b>
 * </p>
 * <p><code>
 *   PKCS12Token token = new PKCS12Token("/path/to/pkcs12/file", "some password") <br/>
 *   List<File> dataFiles = new CDOCDecrypter() <br/>
 *   &nbsp;&nbsp;.withToken(token) <br/>
 *   &nbsp;&nbsp;.withCDOC(new File("/path/to/cdoc")) <br/>
 *   &nbsp;&nbsp;.withCDOCFileSystemHandler(new CustomCDOCFileSystemHandler()) <br/>
 *   &nbsp;&nbsp;.decrypt(new File("path/to/target/directory")); <br/>
 * </code></p>
 */
public class CDOCDecrypter {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(CDOCDecrypter.class);

    private Token token;
    private InputStream cdocInputStream;
    private CDOCFileSystemHandler cdocFileSystemHandler;

    /**
     * Sets the decryption token
     *
     * @param token implementation of {@link Token} used for decryption
     * @return the current instance
     */
    public CDOCDecrypter withToken(Token token) {
        this.token = token;
        return this;
    }

    /**
     * Sets the to be decrypted CDOC
     *
     * @param inputStream of CDOC
     * @return the current instance
     */
    public CDOCDecrypter withCDOC(InputStream inputStream) {
        this.cdocInputStream = inputStream;
        return this;
    }

    /**
     * Sets the to be decrypted CDOC
     *
     * @param file
     * @return the current instance
     */
    public CDOCDecrypter withCDOC(File file) throws FileNotFoundException {
        this.cdocInputStream = new FileInputStream(file);
        return this;
    }

    /**
     * Sets the decryption cdocFileSystemHandler
     *
     * @param cdocFileSystemHandler implementation of {@link CDOCFileSystemHandler} used for handle file creation issues
     * @return the current instance
     */
    public CDOCDecrypter withCDOCFileSystemHandler(CDOCFileSystemHandler cdocFileSystemHandler) {
        this.cdocFileSystemHandler = cdocFileSystemHandler;
        return this;
    }

    /**
     * decrypts the CDOC into given directory and returns a list of decrypted file(s)
     *
     * @throws CDOCException when there's an error decrypting datafile(s) from the given CDOC document
     * @param destinationDirectory where decrypted file(s) will be placed
     * @return list of decrypted file(s)
     */
    public List<File> decrypt(File destinationDirectory) throws CDOCException {
        try {
            destinationDirectory.mkdirs();
            if (!destinationDirectory.isDirectory()) {
                throw new DecryptionException("File path must be an directory!");
            }
            FilePayloadParser payloadParser = new FilePayloadParser(destinationDirectory, cdocFileSystemHandler);
            List<DataFile> dataFiles = decryptCdoc(payloadParser);
            List<File> files = new ArrayList<>();
            for (DataFile dataFile : dataFiles) {
                File file = new File(destinationDirectory.getPath(), dataFile.getName());
                files.add(file);
            }
            return files;
        } finally {
            IOUtils.closeQuietly(cdocInputStream);
        }
    }

    /**
     * decrypts the CDOC and returns a DataFile object list of decrypted file(s)
     *
     * @return DataFile object list of decrypted file(s)
     * @throws CDOCException when there's an error decrypting datafile(s) from the given CDOC document
     */
    public List<DataFile> decrypt() throws CDOCException {
        MemoryPayloadParser payloadParser = new MemoryPayloadParser();
        List<DataFile> dataFiles = decryptCdoc(payloadParser);
        for (DataFile dataFile : dataFiles) {
            dataFile.setMimeType("application/octet-stream");
        }
        return dataFiles;
    }

    /**
     * decrypts the CDOC payload and returns a list of decrypted data file(s)
     *
     * @throws CDOCException when there's an error decrypting file(s) from the given CDOC document
     * @return list of decrypted data file(s)
     */
    private List<DataFile> decryptCdoc(PayloadParser payloadParser) throws CDOCException {
        LOGGER.info("Start decrypting payload from CDOC");
        validateParameters();

        XMLInputFactory xmlInputFactory = WstxInputFactory.newInstance();
        xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false); // This disables DTDs entirely for that factory
        xmlInputFactory.setProperty("javax.xml.stream.isSupportingExternalEntities", false); // disable external entities

        XMLStreamReader xmlReader = null;
        try {
            xmlReader = xmlInputFactory.createXMLStreamReader(cdocInputStream);
            XmlEncParserUtil.goToElement(xmlReader, "EncryptedData");
            String mimeType = XmlEncParserUtil.getAttributeValue(xmlReader, "MimeType");
            XmlEncParserUtil.goToElement(xmlReader, "EncryptionMethod");
            String encryptionMethodUri = XmlEncParserUtil.getAttributeValue(xmlReader, "Algorithm");
            EncryptionMethod encryptionMethod = EncryptionMethod.fromURI(encryptionMethodUri);
            XmlEncParser xmlParser = XmlEncParserFactory.getXmlEncParser(encryptionMethod, xmlReader);
            Recipient recipient = chooseRecipient(xmlParser.getRecipients());
            SecretKey key = decryptKey(recipient, token);

            List<DataFile> dataFiles;
            if (encryptedPayloadIsDDOC(mimeType)) {
                dataFiles = payloadParser.parseAndDecryptDDOC(xmlParser, encryptionMethod, key);
            } else {
                dataFiles = payloadParser.parseAndDecryptPayload(xmlParser, encryptionMethod, key);
            }
            LOGGER.info("Payload decryption completed successfully!");
            return dataFiles;
        } catch (XMLStreamException e) {
            throw new XmlParseException("Failed to parse XML", e);
        } finally {
            if (xmlReader != null) {
                try {
                    xmlReader.close();
                } catch (XMLStreamException e) {
                    throw new IllegalStateException("Failed to close XMLStreamReader", e);
                }
            }
            IOUtils.closeQuietly(cdocInputStream);
        }
    }

    private void validateParameters() throws DecryptionException {
        if (token == null) {
            throw new DecryptionException("Token used for decryption not set!");
        }

        if (cdocInputStream == null) {
            throw new DecryptionException("CDOC to decrypt is not set!");
        }
    }

    protected SecretKey decryptKey(Recipient recipient, Token token) throws CDOCException {
        if (recipient instanceof RSARecipient) {
            return decryptRsaKey((RSARecipient) recipient, token);
        } else if (recipient instanceof ECRecipient) {
            return decryptECKey((ECRecipient) recipient, token);
        } else {
            String message = "Private key algorithm doesn't match with recipient's key algorithm!";
            LOGGER.error(message);
            throw new DecryptionException(message);
        }
    }

    private SecretKey decryptRsaKey(RSARecipient recipient, Token token) throws CDOCException {
        byte[] keyBytes = token.decrypt(recipient);
        return new SecretKeySpec(keyBytes, "AES");
    }

    private SecretKey decryptECKey(ECRecipient recipient, Token token) throws CDOCException {
        if (!isEphemeralPublicKeyValid(recipient.getEphemeralPublicKey())) {
            String message = "Ephemeral public key does not encode a valid point on the used elliptic curve!";
            LOGGER.error(message);
            throw new DecryptionException(message);
        }
        try {
            byte[] sharedSecret = token.decrypt(recipient);

            ConcatenationKDFGenerator concatenationKDFGenerator = new ConcatenationKDFGenerator(new SHA384Digest());
            concatenationKDFGenerator.init(new KDFParameters(sharedSecret, concatenate(recipient.getAlgorithmId(), recipient.getPartyUInfo(), recipient.getPartyVInfo())));
            byte[] wrapperKeyBytes = new byte[32];
            concatenationKDFGenerator.generateBytes(wrapperKeyBytes, 0, 32);
            SecretKeySpec wrapperKey = new SecretKeySpec(wrapperKeyBytes, "AES");

            Cipher cipher = Cipher.getInstance("AESWrap", "BC");
            cipher.init(Cipher.UNWRAP_MODE, wrapperKey);
            return (SecretKey) cipher.unwrap(recipient.getEncryptedKey(), "AES", Cipher.SECRET_KEY);
        } catch (GeneralSecurityException | IOException e) {
            String message = "Error decrypting secret key!";
            LOGGER.error(message, e);
            throw new DecryptionException(message, e);
        }
    }

    private boolean isEphemeralPublicKeyValid(ECPublicKey ephemeralPublicKey) {
        // 1. Verify public key is not a point at infinity
        if (ECPoint.POINT_INFINITY.equals(ephemeralPublicKey.getW())) {
            return false;
        }

        final EllipticCurve ellipticCurve = ephemeralPublicKey.getParams().getCurve();
        final BigInteger x = ephemeralPublicKey.getW().getAffineX();
        final BigInteger y = ephemeralPublicKey.getW().getAffineY();
        final BigInteger p = ((ECFieldFp) ellipticCurve.getField()).getP();

        // 2. Verify x and y are in range [0,p-1]
        if (x.compareTo(BigInteger.ZERO) < 0 || x.compareTo(p) >= 0
                || y.compareTo(BigInteger.ZERO) < 0 || y.compareTo(p) >= 0) {
            return false;
        }

        final BigInteger a = ellipticCurve.getA();
        final BigInteger b = ellipticCurve.getB();

        // 3. Verify that y^2 == x^3 + ax + b mod p
        final BigInteger ySquared = y.modPow(BigInteger.valueOf(2), p);
        final BigInteger xCubedPlusAXPlusB = x.modPow(BigInteger.valueOf(3), p).add(a.multiply(x)).add(b).mod(p);
        if (!ySquared.equals(xCubedPlusAXPlusB)) {
            return false;
        }

        return true;
    }

    private Recipient chooseRecipient(List<Recipient> recipients) throws CDOCException {
        if (recipients.size() > 1) {
            Certificate certificate = token.getCertificate();
            if (certificate == null) {
                String message = "Recipient not set! CDOC contains more than 1 recipients, recipient certificate needs to be set in order to choose the right recipient";
                LOGGER.error(message);
                throw new RecipientMissingException(message);
            } else {
                for (Recipient recipient : recipients) {
                    if (certificate.equals(recipient.getCertificate())) {
                        return recipient;
                    }
                }
                String message = "Configured recipient certificate does not match with any of the recipients in CDOC!";
                LOGGER.error(message);
                throw new RecipientCertificateException(message);
            }
        } else {
            return recipients.get(0);
        }
    }

    private boolean encryptedPayloadIsDDOC(String mimeType) {
        return mimeType.equals("http://www.sk.ee/DigiDoc/v1.3.0/digidoc.xsd");
    }

    private byte[] concatenate(byte[]... byteArrays) throws IOException {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            for (byte[] byteArray : byteArrays) {
                outputStream.write(byteArray);
            }
            return outputStream.toByteArray();
        }
    }

}
