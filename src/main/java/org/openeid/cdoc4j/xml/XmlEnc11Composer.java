package org.openeid.cdoc4j.xml;

import javanet.staxutils.IndentingXMLStreamWriter;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.openeid.cdoc4j.DataFile;
import org.openeid.cdoc4j.crypto.CertUtil;
import org.openeid.cdoc4j.crypto.CryptUtil;
import org.openeid.cdoc4j.crypto.KeyGenUtil;
import org.openeid.cdoc4j.exception.CDOCException;
import org.openeid.cdoc4j.exception.EncryptionException;
import org.openeid.cdoc4j.exception.RecipientCertificateException;
import org.openeid.cdoc4j.stream.ClosableBase64OutputStream;
import org.openeid.cdoc4j.xml.exception.XmlTransformException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

public class XmlEnc11Composer extends XmlEncComposer {

    private static final Logger LOGGER = LoggerFactory.getLogger(XmlEncComposer.class);

    protected static final String ENCDOC_XML_VERSION = "ENCDOC-XML|1.1";

    private KeyPair ephemeralKeyPair;
    private byte[] partyUInfo;
    private byte[] partyVInfo;

    @Override
    protected void createRecipientEncryptedKeyElement(X509Certificate certificate) throws CDOCException, XMLStreamException {
        if (certificate.getPublicKey() instanceof RSAPublicKey) {
            super.createRecipientEncryptedKeyElement(certificate);
        } else if (certificate.getPublicKey() instanceof ECPublicKey) {
            createECRecipientEncryptedKey(certificate);
        } else {
            String message = "Recipient's: " + certificate.getSubjectDN().getName() + " certificate contains unknown key algorithm: " + certificate.getPublicKey().getAlgorithm();
            LOGGER.error(message);
            throw new RecipientCertificateException(message);
        }
    }

    private void createECRecipientEncryptedKey(X509Certificate certificate) throws CDOCException, XMLStreamException {
        writer.writeStartElement(xmlEncPrefix("EncryptedKey"));
        writer.writeAttribute("Recipient", CertUtil.getCN(certificate));
        createEncryptionMethodElement("http://www.w3.org/2001/04/xmlenc#kw-aes256");
        createECKeyInfoElement(certificate);
        createRecipientCipherDataElement(certificate);
        writer.writeEndElement();
    }

    protected void createECKeyInfoElement(X509Certificate certificate) throws CDOCException, XMLStreamException {
        writer.writeStartElement(xmlSigPrefix("KeyInfo"));
        createAgreementMethodElement(certificate);
        writer.writeEndElement();
    }

    private void createAgreementMethodElement(X509Certificate certificate) throws XMLStreamException, CDOCException {
        writer.writeStartElement(xmlEncPrefix("AgreementMethod"));
        writer.writeAttribute("Algorithm", "http://www.w3.org/2009/xmlenc11#ECDH-ES");

        ECPublicKey ecPublicKey = (ECPublicKey) certificate.getPublicKey();
        try {
            ephemeralKeyPair = KeyGenUtil.generateECKeyPair(ecPublicKey);
        } catch (GeneralSecurityException e) {
            String message = "Error generating EC KeyPair";
            LOGGER.error(message, e);
            throw new CDOCException(message, e);
        }

        partyUInfo = SubjectPublicKeyInfo.getInstance(ephemeralKeyPair.getPublic().getEncoded()).getPublicKeyData().getBytes();
        try {
            partyVInfo = certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            String message = "Error encoding certificate: " + certificate.getSubjectDN().getName();
            LOGGER.error(message, e);
            throw new RecipientCertificateException(message, e);
        }
        String curveOID = SubjectPublicKeyInfo.getInstance(ecPublicKey.getEncoded()).getAlgorithm().getParameters().toString();

        createKeyDerivationMethod();
        createOriginatorKeyInfo(curveOID);
        createRecipientKeyInfo(certificate);

        writer.writeEndElement();
    }

    private void createKeyDerivationMethod() throws XMLStreamException {
        writer.writeStartElement("xenc11:KeyDerivationMethod");
        writer.writeAttribute("xmlns:xenc11", "http://www.w3.org/2009/xmlenc11#");
        writer.writeAttribute("Algorithm", "http://www.w3.org/2009/xmlenc11#ConcatKDF");
        createConcatKDFParamsElement();
        writer.writeEndElement();
    }

    private void createConcatKDFParamsElement() throws XMLStreamException {
        writer.writeStartElement("xenc11:ConcatKDFParams");
        writer.writeAttribute("AlgorithmID", "00" + Hex.toHexString(ENCDOC_XML_VERSION.getBytes()));
        writer.writeAttribute("PartyUInfo", "00" + Hex.toHexString(partyUInfo));
        writer.writeAttribute("PartyVInfo", "00" + Hex.toHexString(partyVInfo));
        createDigestMethodElement();
        writer.writeEndElement();
    }

    private void createDigestMethodElement() throws XMLStreamException {
        writer.writeStartElement(xmlSigPrefix("DigestMethod"));
        writer.writeAttribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha384");
        writer.writeEndElement();
    }

    private void createOriginatorKeyInfo(String curveOID) throws XMLStreamException {
        writer.writeStartElement(xmlEncPrefix("OriginatorKeyInfo"));
        createKeyValueElement(curveOID);
        writer.writeEndElement();
    }

    private void createKeyValueElement(String curveOID) throws XMLStreamException {
        writer.writeStartElement(xmlSigPrefix("KeyValue"));
        createECKeyValueElement(curveOID);
        writer.writeEndElement();
    }

    private void createECKeyValueElement(String curveOID) throws XMLStreamException {
        writer.writeStartElement("dsig11:ECKeyValue");
        writer.writeAttribute("xmlns:dsig11", "http://www.w3.org/2009/xmldsig11#");
        createNamedCurveElement(curveOID);
        createPublicKeyElement();
        writer.writeEndElement();
    }

    private void createNamedCurveElement(String curveOID) throws XMLStreamException {
        writer.writeStartElement("dsig11:NamedCurve");
        String curveName = "urn:oid:" + curveOID;
        writer.writeAttribute("URI", curveName);
        writer.writeEndElement();
    }

    private void createPublicKeyElement() throws XMLStreamException {
        writer.writeStartElement("dsig11:PublicKey");
        writer.writeCharacters(Base64.toBase64String(partyUInfo));
        writer.writeEndElement();
    }

    private void createRecipientKeyInfo(X509Certificate certificate) throws RecipientCertificateException, XMLStreamException {
        writer.writeStartElement(xmlEncPrefix("RecipientKeyInfo"));
        super.createX509DataElement(certificate);
        writer.writeEndElement();
    }

    private void createRecipientCipherDataElement(X509Certificate certificate) throws CDOCException, XMLStreamException {
        writer.writeStartElement(xmlEncPrefix("CipherData"));
        createRecipientCipherValueElement(certificate);
        writer.writeEndElement();
    }

    private void createRecipientCipherValueElement(X509Certificate certificate) throws CDOCException, XMLStreamException {
        writer.writeStartElement(xmlEncPrefix("CipherValue"));

        byte[] sharedSecret;
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(ephemeralKeyPair.getPrivate());
            keyAgreement.doPhase(certificate.getPublicKey(), true);
            sharedSecret = keyAgreement.generateSecret();
        } catch (GeneralSecurityException e) {
            String message = "Error generating ECDH key agreement!";
            LOGGER.error(message, e);
            throw new CDOCException(message, e);
        }

        try {
            byte[] wrapKeyBytes = new byte[32];
            ConcatenationKDFGenerator concatenationKDFGenerator = new ConcatenationKDFGenerator(new SHA384Digest());
            concatenationKDFGenerator.init(new KDFParameters(sharedSecret, concatenate(ENCDOC_XML_VERSION.getBytes(), partyUInfo, partyVInfo)));
            concatenationKDFGenerator.generateBytes(wrapKeyBytes, 0, 32);

            SecretKeySpec wrapKey = new SecretKeySpec(wrapKeyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AESWrap");
            cipher.init(Cipher.WRAP_MODE, wrapKey);
            byte[] wrappedKey = cipher.wrap(secretKey);
            writer.writeCharacters(Base64.toBase64String(wrappedKey));
        } catch (GeneralSecurityException | IOException e) {
            String message = "Error generating ECDH key agreement!";
            LOGGER.error(message, e);
            throw new CDOCException(message, e);
        }

        writer.writeEndElement();
    }

    private byte[] concatenate(byte[]... bytes) throws IOException {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            for (int i = 0; i < bytes.length; i++) {
                outputStream.write(bytes[i]);
            }
            return outputStream.toByteArray();
        }
    }

    @Override
    protected void encryptAndBase64EncodeSingleDataFile() throws EncryptionException {
        byte[] IV = CryptUtil.generateIV(12);

        try (ClosableBase64OutputStream outputStream = new ClosableBase64OutputStream(output)) {
            outputStream.write(IV);
            encryptDataFile(outputStream, dataFiles.get(0), IV);
        } catch (IOException e) {
            throw formEncryptionException("Failed to base64 encode data file content", e);
        }
    }

    protected void encryptDataFile(OutputStream outputStream, DataFile dataFile, byte[] IV) throws EncryptionException {
        try (InputStream dataToEncrypt = dataFile.getContent()) {
            CryptUtil.encryptAesGcm(outputStream, dataToEncrypt, secretKey, IV);
        } catch (IOException | GeneralSecurityException e) {
            throw formEncryptionException("Error encrypting data file!", e);
        }
    }

    @Override
    protected void constructDataFilesXml() throws CDOCException, XMLStreamException {
        byte[] IV = CryptUtil.generateIV(12);
        Cipher cipher = constructEncryptionCipher(IV);

        XMLStreamWriter ddocWriter = null;
        try (
            ClosableBase64OutputStream base64EncoderStream = new ClosableBase64OutputStream(output);
            CipherOutputStream cipherOutput = new CipherOutputStream(base64EncoderStream, cipher)
        ) {
            base64EncoderStream.write(IV);
            ddocWriter = new IndentingXMLStreamWriter(factory.createXMLStreamWriter(cipherOutput));
            constructAndEncryptDDOC(ddocWriter, cipherOutput);
        } catch (IOException | EncryptionException | XMLStreamException e) {
            String message = "Error transforming DDOC xml!";
            LOGGER.error(message, e);
            throw new XmlTransformException(message, e);
        } finally {
            if (ddocWriter != null) {
                ddocWriter.close();
            }
        }
    }

    private Cipher constructEncryptionCipher(byte[] IV) throws EncryptionException {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec params = new GCMParameterSpec(128, IV);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, params);
            return cipher;
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            throw new EncryptionException("Failed to construct AES GCM encryption cipher", e);
        }
    }

    @Override
    protected String getEncDocXmlVersion() {
        return ENCDOC_XML_VERSION;
    }

} 
