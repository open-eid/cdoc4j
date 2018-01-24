package org.openeid.cdoc4j;

import org.openeid.cdoc4j.pkcs11.PKCS11Token;
import org.openeid.cdoc4j.crypto.CryptUtil;
import org.openeid.cdoc4j.exception.CDOCException;
import org.openeid.cdoc4j.exception.DecryptionException;
import org.openeid.cdoc4j.exception.PrivateKeyMissingException;
import org.openeid.cdoc4j.exception.RecipientCertificateException;
import org.openeid.cdoc4j.exception.RecipientMissingException;
import org.openeid.cdoc4j.xml.DDOCParser;
import org.openeid.cdoc4j.xml.XMLDocumentBuilder;
import org.openeid.cdoc4j.xml.XmlEncParser;
import org.openeid.cdoc4j.xml.XmlEncParserFactory;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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
 * Required parameters for soft cert usage (a.k.a. for testing purposes):
 * <ul>
 * <li><b>{@link PrivateKey}</b> - required for the recipient to decrypt the file(s))</li>
 * <li><b>{@link X509Certificate}</b> - (only required when the to be encrypted CDOC recipient count is more than one)</li>
 * </ul>
 * Required parameters for HSM (Hardware Security Module) usage:
 * <ul>
 * <li><b>{@link String}</b> - path to the reachable (and usable) PKCS#11 (proxy) driver from the machine</li>
 * <li><b>{@link String}</b> - the required PIN to allow to perform the cryptographic operation on the HSM device</li>
 * <li><b>{@link Integer}</b> - the slot used by the driver to connect to the actual HSM</li>
 * </ul>
 */
public class CDOCDecrypter {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(CDOCDecrypter.class);

    private PKCS11TokenParams pkcs11Params;

    private PrivateKey privateKey;

    private Certificate certificate;

    /**
     * Sets the recipient certificate (for soft cert usage; only required when CDOC contains more than one recipient)
     *
     * @param certificate of the recipient
     * @return the current instance
     */
    public CDOCDecrypter asRecipient(X509Certificate certificate) {
        this.certificate = certificate;
        return this;
    }

    /**
     * Sets the recipient
     *
     * @param inputStream of the recipient's certificate (for soft cert usage; only required when CDOC contains more than one recipient)
     * @throws RecipientCertificateException when there's an error reading the certificate from input stream
     * @return the current instance
     */
    public CDOCDecrypter asRecipient(InputStream inputStream) throws RecipientCertificateException {
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(inputStream);
            return asRecipient(certificate);
        } catch (CertificateException e) {
            String message = "Error reading certificate from input stream!";
            LOGGER.error(message, e);
            throw new RecipientCertificateException(message, e);
        }
    }

    /**
     * Sets the private key input stream (for soft cert usage)
     *
     * @param privateKey of the recipient
     * @return the current instance
     */
    public CDOCDecrypter withPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
        return this;
    }

    /**
     * Sets the private key input stream (for soft cert usage)
     *
     * @param pemInputStream of the recipient's private key
     * @throws CDOCException when there's an error reading the private key from PEM input stream
     * @return the current instance
     */
    public CDOCDecrypter withPrivateKey(InputStream pemInputStream) throws CDOCException {
        withPrivateKey(getPrivateKeyFromPEM(pemInputStream));
        return this;
    }

    /**
     * Sets the PKCS#11 input parameters
     *
     * @param params for the PKCS#11 usage
     * @return the current instance
     */
    public CDOCDecrypter withPkcs11(PKCS11TokenParams params) {
        pkcs11Params = params;
        return this;
    }

    /**
     * Sets the PKCS#11 input parameters
     *
     * @param pkcs11Path path to the PKCS#11 driver
     * @param pin of the HSM to perform the cryptographic operation
     * @param slot used by the driver to connect to the actual HSM
     * @return the current instance
     */
    public CDOCDecrypter withPkcs11(String pkcs11Path, String pin, int slot) {
        pkcs11Params = new PKCS11TokenParams(pkcs11Path, pin, slot);
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
        PKCS11Token token = null;
        if (pkcs11Params != null) {
            token = initPkcs11(pkcs11Params);
        }
        if (privateKey == null) {
            throw new PrivateKeyMissingException("Private key not set!");
        }

        Document document = XMLDocumentBuilder.buildDocument(inputStream);
        XmlEncParser cdocparser = XmlEncParserFactory.getXmlEncParser(document);

        Recipient recipient = chooseRecipient(cdocparser.getRecipients());

        byte[] encryptedPayload = cdocparser.getEncryptedPayload();
        EncryptionMethod encryptionMethod = cdocparser.getEncryptionMethod();

        SecretKey key = decryptKey(recipient, privateKey);
        byte[] decryptedPayload = decryptPayload(encryptionMethod, encryptedPayload, key);

        if (token != null) {
            token.removeProvider();
        }

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

    private Recipient chooseRecipient(List<Recipient> recipients) throws RecipientMissingException, RecipientCertificateException {
        if (recipients.size() > 1) {
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

    private PrivateKey getPrivateKeyFromPEM(InputStream pemInputStream) throws CDOCException {
        try {
            PEMParser pemParser = new PEMParser(new InputStreamReader(pemInputStream));
            Object privateKey = pemParser.readObject();

            if (privateKey instanceof PEMKeyPair) {
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
                PrivateKeyInfo keyInfo = ((PEMKeyPair) privateKey).getPrivateKeyInfo();
                return converter.getPrivateKey(keyInfo);
            }
            return null;
        } catch (IOException e) {
            String message = "Error reading private key from input stream!";
            LOGGER.error(message, e);
            throw new CDOCException(message, e);
        }
    }

    private PKCS11Token initPkcs11(PKCS11TokenParams params) throws CDOCException {
        try {
            LOGGER.debug("Initializing PKCS#11");
            PKCS11Token token = new PKCS11Token(params.getPkcs11Path(), params.getPin().toCharArray(), params.getSlot());
            KeyStore.PrivateKeyEntry privateKeyEntry = token.getKeys().get(0);
            certificate = privateKeyEntry.getCertificate();
            privateKey = privateKeyEntry.getPrivateKey();
            LOGGER.debug("PKCS#11 initialized successfully!");
            return token;
        } catch (Exception e) {
            String message = "Error initializing PKCS#11!";
            LOGGER.error(message, e);
            throw new CDOCException(message, e);
        }
    }

    private SecretKey decryptKey(Recipient recipient, PrivateKey privateKey) throws DecryptionException {
        if (recipient instanceof RSARecipient && "RSA".equals(privateKey.getAlgorithm())) {
            return decryptRsaKey((RSARecipient) recipient, privateKey);
        } else if (recipient instanceof ECRecipient && privateKey.getAlgorithm().startsWith("EC")) {
            return decryptECKey((ECRecipient) recipient, privateKey);
        } else {
            String message = "Private key algorithm doesn't match with recipient's key algorithm!";
            LOGGER.error(message);
            throw new DecryptionException(message);
        }
    }

    private SecretKey decryptRsaKey(RSARecipient recipient, PrivateKey privateKey) throws DecryptionException {
        try {
            byte[] keyBytes = CryptUtil.decryptRsa(recipient.getEncryptedKey(), privateKey);
            return new SecretKeySpec(keyBytes, "AES");
        } catch (GeneralSecurityException e) {
            String message = "Error decrypting secret key!";
            LOGGER.error(message, e);
            throw new DecryptionException(message, e);
        }
    }

    private SecretKey decryptECKey(ECRecipient recipient, PrivateKey privateKey) throws DecryptionException {
        if (!isEphemeralPublicKeyValid(recipient.getEphemeralPublicKey())) {
            String message = "Ephemeral public key does not encode a valid point on the used elliptic curve!";
            LOGGER.error(message);
            throw new DecryptionException(message);
        }
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(recipient.getEphemeralPublicKey(), true);
            byte[] sharedSecret = keyAgreement.generateSecret();

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
