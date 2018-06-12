package org.openeid.cdoc4j.xml;

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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

public class XmlEnc11Composer extends XmlEncComposer {

    private static final Logger LOGGER = LoggerFactory.getLogger(XmlEncComposer.class);

    protected static final String ENCDOC_XML_VERSION = "ENCDOC-XML|1.1";

    @Override
    protected Element createRecipientEncryptedKey(SecretKey key, X509Certificate certificate) throws CDOCException {
        if (certificate.getPublicKey() instanceof RSAPublicKey) {
            return super.createRecipientEncryptedKey(key, certificate);
        } else if (certificate.getPublicKey() instanceof ECPublicKey) {
            return createECRecipientEncryptedKey(key, certificate);
        } else {
            String message = "Recipient's: " + certificate.getSubjectDN().getName() + " certificate contains unknown key algorithm: " + certificate.getPublicKey().getAlgorithm();
            LOGGER.error(message);
            throw new RecipientCertificateException(message);
        }
    }

    protected Element createECRecipientEncryptedKey(SecretKey key, X509Certificate certificate) throws CDOCException {
        Element encryptedKey = document.createElement("denc:EncryptedKey");
        encryptedKey.setAttribute("Recipient", CertUtil.getCN(certificate));

        Element encryptionMethod = createEncryptionMethod("http://www.w3.org/2001/04/xmlenc#kw-aes256");
        encryptedKey.appendChild(encryptionMethod);

        Element keyInfo = document.createElement("ds:KeyInfo");

        Element agreementMethod = document.createElement("denc:AgreementMethod");
        agreementMethod.setAttribute("Algorithm", "http://www.w3.org/2009/xmlenc11#ECDH-ES");

        ECPublicKey ecPublicKey = (ECPublicKey) certificate.getPublicKey();
        KeyPair ephemeralKeyPair;
        try {
            ephemeralKeyPair = KeyGenUtil.generateECKeyPair(ecPublicKey);
        } catch (GeneralSecurityException e) {
            String message = "Error generating EC KeyPair";
            LOGGER.error(message, e);
            throw new CDOCException(message, e);
        }

        byte[] partyUInfo = SubjectPublicKeyInfo.getInstance(ephemeralKeyPair.getPublic().getEncoded()).getPublicKeyData().getBytes();
        byte[] partyVInfo;
        try {
            partyVInfo = certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            String message = "Error encoding certificate: " + certificate.getSubjectDN().getName();
            LOGGER.error(message, e);
            throw new RecipientCertificateException(message, e);
        }
        String curveOID = SubjectPublicKeyInfo.getInstance(ecPublicKey.getEncoded()).getAlgorithm().getParameters().toString();

        agreementMethod.appendChild(createKeyDerivationMethod(partyUInfo, partyVInfo));
        agreementMethod.appendChild(createOriginatorKeyInfo(partyUInfo, curveOID));
        agreementMethod.appendChild(createRecipientKeyInfo(certificate));

        keyInfo.appendChild(agreementMethod);
        encryptedKey.appendChild(keyInfo);
        encryptedKey.appendChild(createRecipientCipherData(key, ephemeralKeyPair, certificate, partyUInfo, partyVInfo));
        return encryptedKey;
    }

    private Element createKeyDerivationMethod(byte[] partyUInfo, byte[] partyVInfo) throws RecipientCertificateException {
        Element keyDerivationMethod = document.createElement("xenc11:KeyDerivationMethod");
        keyDerivationMethod.setAttribute("xmlns:xenc11", "http://www.w3.org/2009/xmlenc11#");
        keyDerivationMethod.setAttribute("Algorithm", "http://www.w3.org/2009/xmlenc11#ConcatKDF");

        Element concatKDFParams = document.createElement("xenc11:ConcatKDFParams");
        concatKDFParams.setAttribute("AlgorithmID", "00" + Hex.toHexString(ENCDOC_XML_VERSION.getBytes()));
        concatKDFParams.setAttribute("PartyUInfo", "00" + Hex.toHexString(partyUInfo));
        concatKDFParams.setAttribute("PartyVInfo", "00" + Hex.toHexString(partyVInfo));

        Element digestMethod = document.createElement("ds:DigestMethod");
        digestMethod.setAttribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha384");
        concatKDFParams.appendChild(digestMethod);

        keyDerivationMethod.appendChild(concatKDFParams);

        return keyDerivationMethod;
    }

    private Element createOriginatorKeyInfo(byte[] partyUInfo, String curveOID) {
        Element originatorKeyInfo = document.createElement("denc:OriginatorKeyInfo");
        Element keyValue = document.createElement("ds:KeyValue");
        Element eckeyValue = document.createElement("dsig11:ECKeyValue");
        eckeyValue.setAttribute("xmlns:dsig11", "http://www.w3.org/2009/xmldsig11#");

        Element namedCurve = document.createElement("dsig11:NamedCurve");
        String curveName = "urn:oid:" + curveOID;
        namedCurve.setAttribute("URI", curveName);
        eckeyValue.appendChild(namedCurve);

        Element publicKey = document.createElement("dsig11:PublicKey");
        publicKey.setTextContent(Base64.toBase64String(partyUInfo));
        eckeyValue.appendChild(publicKey);

        keyValue.appendChild(eckeyValue);
        originatorKeyInfo.appendChild(keyValue);
        return originatorKeyInfo;
    }

    private Node createRecipientKeyInfo(X509Certificate certificate) throws RecipientCertificateException {
        Element recipientKeyInfo = document.createElement("denc:RecipientKeyInfo");
        Element x509data = document.createElement("ds:X509Data");

        Element x509Certificate = document.createElement("ds:X509Certificate");
        try {
            x509Certificate.setTextContent(Base64.toBase64String(certificate.getEncoded()));
        } catch (CertificateEncodingException e) {
            String message = "Error encoding certificate: " + certificate.getSubjectDN().getName();
            LOGGER.error(message, e);
            throw new RecipientCertificateException(message, e);
        }

        x509data.appendChild(x509Certificate);
        recipientKeyInfo.appendChild(x509data);
        return recipientKeyInfo;
    }

    private Node createRecipientCipherData(SecretKey key, KeyPair ephemeralKeyPair, X509Certificate certificate, byte[] partyUInfo, byte[] partyVInfo) throws CDOCException {
        Element cipherData = document.createElement("denc:CipherData");
        Element cipherValue = document.createElement("denc:CipherValue");

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
            Cipher c = Cipher.getInstance("AESWrap");
            c.init(Cipher.WRAP_MODE, wrapKey);
            byte[] wrappedKey = c.wrap(key);
            cipherValue.setTextContent(Base64.toBase64String(wrappedKey));
        } catch (GeneralSecurityException | IOException e) {
            String message = "Error generating ECDH key agreement!";
            LOGGER.error(message, e);
            throw new CDOCException(message, e);
        }
        
        cipherData.appendChild(cipherValue);

        return cipherData;
    }

    @Override
    protected Element createCipherData(SecretKey key, List<DataFile> dataFiles) throws CDOCException {
        Element cipherData = document.createElement("denc:CipherData");
        Element cipherValue = document.createElement("denc:CipherValue");

        byte[] dataToEncrypt;
        if (dataFiles.size() > 1) {
            LOGGER.debug("Multiple data files set - composing data files DDOC..");
            dataToEncrypt = constructDataFilesXml(dataFiles);
        } else {
            dataToEncrypt = dataFiles.get(0).getContent();
        }
        try {
            byte[] iv = CryptUtil.generateIV(12);
            byte[] encryptedDataFiles = CryptUtil.encryptAesGcm(dataToEncrypt, key, iv);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            byteArrayOutputStream.write(iv);
            byteArrayOutputStream.write(encryptedDataFiles);

            cipherValue.setTextContent(Base64.toBase64String(byteArrayOutputStream.toByteArray()));
        } catch (GeneralSecurityException | IOException e) {
            String message = "Error encrypting data files!";
            LOGGER.error(message, e);
            throw new EncryptionException(message, e);
        }
        cipherData.appendChild(cipherValue);
        return cipherData;
    }

    private byte[] concatenate(byte[]... bytes) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        for (int i = 0; i < bytes.length; i++) {
            outputStream.write(bytes[i]);
        }
        return outputStream.toByteArray();
    }

    @Override
    protected String getEncDocXmlVersion() {
        return ENCDOC_XML_VERSION;
    }

} 
