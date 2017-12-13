package org.cdoc4j;

import org.cdoc4j.crypto.CryptUtil;
import org.cdoc4j.exception.CDOCException;
import org.cdoc4j.exception.DecryptionException;
import org.cdoc4j.exception.PrivateKeyMissingException;
import org.cdoc4j.exception.RecipientCertificateException;
import org.cdoc4j.exception.RecipientMissingException;
import org.cdoc4j.xml.DDOCParser;
import org.cdoc4j.xml.XMLDocumentBuilder;
import org.cdoc4j.xml.XmlEncParser;
import org.cdoc4j.xml.XmlEncParserFactory;
import eu.europa.esig.dss.token.KSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs11SignatureToken;
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
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class CDOCDecrypter {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(CDOCDecrypter.class);

    private PrivateKey privateKey;

    private Certificate certificate;

    public CDOCDecrypter asRecipient(X509Certificate certificate) throws RecipientCertificateException {
        this.certificate = certificate;
        return this;
    }

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

    public CDOCDecrypter withPrivateKey(InputStream pemInputStream) throws CDOCException {
        privateKey = getPrivateKey(pemInputStream);
        return this;
    }

    public CDOCDecrypter withPkcs11(String pkcs11Path, long slot, String pin) throws CDOCException {
        initPkcs11(pkcs11Path, slot, pin);
        return this;
    }

    public List<DataFile> decrypt(InputStream cdocInputStream) throws CDOCException {
        if (privateKey == null) {
            throw new PrivateKeyMissingException("Private key not set!");
        }

        Document document = XMLDocumentBuilder.buildDocument(cdocInputStream);
        XmlEncParser cdocparser = XmlEncParserFactory.getXmlEncParser(document);

        Recipient recipient = chooseRecipient(cdocparser.getRecipients());

        byte[] encryptedPayload = cdocparser.getEncryptedPayload();
        EncryptionMethod encryptionMethod = cdocparser.getEncryptionMethod();

        SecretKey key = decryptKey(recipient, privateKey);
        byte[] decryptedPayload = decryptPayload(encryptionMethod, encryptedPayload, key);

        if (cdocparser.encryptedPayloadIsDDOC()) {
            DDOCParser ddocParser = new DDOCParser(decryptedPayload);
            return ddocParser.getDataFiles();
        } else {
            String fileName = cdocparser.getOriginalFileName();
            DataFile dataFile = new DataFile(fileName, decryptedPayload);
            return new ArrayList<>(Collections.singletonList(dataFile));
        }
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

    private PrivateKey getPrivateKey(InputStream pemInputStream) throws CDOCException {
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

    private void initPkcs11(String pkcs11Path, long slot, String pin) throws CDOCException {
        try {
            Pkcs11SignatureToken signatureToken = new Pkcs11SignatureToken(pkcs11Path, pin.toCharArray(), (int) slot);
            KSPrivateKeyEntry privateKeyEntry = (KSPrivateKeyEntry) signatureToken.getKeys().get(0);
            certificate = privateKeyEntry.getCertificate().getCertificate();
            privateKey = privateKeyEntry.getPrivateKey();
        } catch (Exception e) {
            String message = "Error with PKCS11!";
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
