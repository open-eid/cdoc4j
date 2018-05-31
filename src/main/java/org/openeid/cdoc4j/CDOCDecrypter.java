package org.openeid.cdoc4j;

import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openeid.cdoc4j.crypto.CryptUtil;
import org.openeid.cdoc4j.exception.CDOCException;
import org.openeid.cdoc4j.exception.DecryptionException;
import org.openeid.cdoc4j.exception.RecipientCertificateException;
import org.openeid.cdoc4j.exception.RecipientMissingException;
import org.openeid.cdoc4j.token.Token;
import org.openeid.cdoc4j.xml.DDOCParser;
import org.openeid.cdoc4j.xml.XMLDocumentBuilder;
import org.openeid.cdoc4j.xml.XmlEncParser;
import org.openeid.cdoc4j.xml.XmlEncParserFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Class for decrypting CDOC documents (supports 1.0 and 1.1)
 * <p>
 *   <b>Example of decrypting CDOC document with PKCS#11:</b>
 * </p>
 * <p><code>
 *   PKCS11TokenParams params = new PKCS11TokenParams("/path/to/pkcs11/driver", "your PIN1", 0);
 *   PKCS11Token token = new PKCS11Token(params) <br/>
 *   List<DataFile> dataFiles = new CDOCDecrypter() <br/>
 *   &nbsp;&nbsp;.withToken(token) <br/>
 *   &nbsp;&nbsp;.decrypt(new FileInputStream(cdoc)); <br/>
 * </code></p>
 * <p>
 *   <b>Example of decrypting CDOC document with PKCS#12:</b>
 * </p>
 * <p><code>
 *   PKCS12Token token = new PKCS12Token("/path/to/pkcs12/file", "some password") <br/>
 *   List<DataFile> dataFiles = new CDOCDecrypter() <br/>
 *   &nbsp;&nbsp;.withToken(token) <br/>
 *   &nbsp;&nbsp;.decrypt(new FileInputStream(cdoc)); <br/>
 * </code></p>
 */
public class CDOCDecrypter {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(CDOCDecrypter.class);

    private Token token;

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
     * decrypts the CDOC payload and returns the decrypted file(s)
     *
     * @param inputStream of the CDOC document
     * @throws CDOCException when there's an error decrypting datafile(s) from the given CDOC document
     * @return decrypted datafile(s)
     */
    public List<DataFile> decrypt(InputStream inputStream) throws CDOCException {
        LOGGER.info("Start decrypting payload from CDOC");
        if (token == null) {
            throw new DecryptionException("Token used for decryption not set!");
        }

        Document document = XMLDocumentBuilder.buildDocument(inputStream);
        XmlEncParser cdocparser = XmlEncParserFactory.getXmlEncParser(document);

        Recipient recipient = chooseRecipient(cdocparser.getRecipients());

        byte[] encryptedPayload = cdocparser.getEncryptedPayload();
        EncryptionMethod encryptionMethod = cdocparser.getEncryptionMethod();

        SecretKey key = decryptKey(recipient, token);
        byte[] decryptedPayload = decryptPayload(encryptionMethod, encryptedPayload, key);

        List<DataFile> dataFiles;
        if (cdocparser.encryptedPayloadIsDDOC()) {
            LOGGER.debug("Encrypted payload is DDOC, decrypting..");
            DDOCParser ddocParser = new DDOCParser(decryptedPayload);
            dataFiles = ddocParser.getDataFiles();
        } else {
            LOGGER.debug("Encrypted payload is a single file, decrypting..");
            String fileName = cdocparser.getOriginalFileName();
            DataFile dataFile = new DataFile(fileName, decryptedPayload);
            dataFiles = new ArrayList<>(Collections.singletonList(dataFile));
        }
        LOGGER.info("Payload decryption completed successfully!");
        return dataFiles;
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

    private SecretKey decryptKey(Recipient recipient, Token token) throws CDOCException {
        if (recipient instanceof RSARecipient) {
            return decryptRsaKey((RSARecipient) recipient,token);
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

            Cipher cipher = Cipher.getInstance("AESWrap");
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

    private byte[] concatenate(byte[]... bytes) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        for (int i = 0; i < bytes.length; i++) {
            outputStream.write(bytes[i]);
        }
        return outputStream.toByteArray();
    }

    private byte[] decryptPayload(EncryptionMethod encryptionMethod, byte[] encryptedBytes, SecretKey key) throws DecryptionException {
        try {
            if (EncryptionMethod.AES_128_CBC == encryptionMethod) {
                byte[] iv = Arrays.copyOfRange(encryptedBytes, 0, 16);
                byte[] bytesToDecrypt = Arrays.copyOfRange(encryptedBytes, 16, encryptedBytes.length);
                return CryptUtil.decryptAesCbc(bytesToDecrypt, key, iv);
            } else {
                byte[] iv = Arrays.copyOfRange(encryptedBytes, 0, 12);
                byte[] bytesToDecrypt = Arrays.copyOfRange(encryptedBytes, 12, encryptedBytes.length);
                return CryptUtil.decryptAesGcm(bytesToDecrypt, key, iv);
            }
        } catch (GeneralSecurityException | IOException e) {
            String message = "Error decrypting payload!";
            LOGGER.error(message, e);
            throw new DecryptionException(message, e);
        }
    }

}
