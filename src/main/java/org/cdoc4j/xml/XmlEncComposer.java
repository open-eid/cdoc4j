package org.cdoc4j.xml;

import org.cdoc4j.DataFile;
import org.cdoc4j.crypto.CertUtil;
import org.cdoc4j.crypto.CryptUtil;
import org.cdoc4j.exception.CDOCException;
import org.cdoc4j.exception.EncryptionException;
import org.cdoc4j.exception.RecipientCertificateException;
import org.cdoc4j.xml.exception.XmlTransformException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FilenameUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.crypto.SecretKey;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

public class XmlEncComposer {

    private static final Logger LOGGER = LoggerFactory.getLogger(XmlEncComposer.class);

    protected static final String ENCODING = "UTF-8";
    protected static final String DDOC_MIMETYPE = "http://www.sk.ee/DigiDoc/v1.3.0/digidoc.xsd";
    protected static final String ENCDOC_XML_VERSION = "ENCDOC-XML|1.0";

    protected Document document;

    public byte[] constructXML(String encryptionMethodUri, SecretKey key, List<X509Certificate> recipients, List<DataFile> dataFiles) throws CDOCException {
        document = XMLDocumentBuilder.createDocument();
        Element root = createEncryptedData(dataFiles.size());
        root.appendChild(createEncryptionMethod(encryptionMethodUri));
        root.appendChild(createRecipientsKeyInfo(key, recipients));
        root.appendChild(createCipherData(key, dataFiles));
        root.appendChild(createEncryptionProperties(dataFiles));
        document.appendChild(root);
        return transformToXml(document);
    }

    protected Element createEncryptedData(int dataFilesSize) {
        Element encryptedData = document.createElement("denc:EncryptedData");
        encryptedData.setAttribute("xmlns:denc", "http://www.w3.org/2001/04/xmlenc#");
        if (dataFilesSize > 1) {
            encryptedData.setAttribute("MimeType", DDOC_MIMETYPE);
        } else {
            encryptedData.setAttribute("MimeType", "application/octet-stream");
        }
        return encryptedData;
    }

    protected Element createEncryptionMethod(String algorithmUri) {
        Element encryptionMethod = document.createElement("denc:EncryptionMethod");
        encryptionMethod.setAttribute("Algorithm", algorithmUri);
        return encryptionMethod;
    }

    protected Element createRecipientsKeyInfo(SecretKey key, List<X509Certificate> recipients) throws CDOCException {
        Element keyInfo = document.createElement("ds:KeyInfo");
        keyInfo.setAttribute("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#");

        for (X509Certificate certificate : recipients) {
            keyInfo.appendChild(createRecipientEncryptedKey(key, certificate));
        }

        return keyInfo;
    }

    protected Element createRecipientEncryptedKey(SecretKey key, X509Certificate certificate) throws CDOCException {
        Element encryptedKey = document.createElement("denc:EncryptedKey");
        encryptedKey.setAttribute("Recipient", CertUtil.getCN(certificate));

        Element encryptionMethod = createEncryptionMethod("http://www.w3.org/2001/04/xmlenc#rsa-1_5");
        encryptedKey.appendChild(encryptionMethod);

        Element keyInfo = document.createElement("ds:KeyInfo");
        Element x509Data = document.createElement("ds:X509Data");
        keyInfo.appendChild(x509Data);
        try {
            Element x509Certificate = document.createElement("ds:X509Certificate");
            x509Certificate.setTextContent(Base64.encodeBase64String(certificate.getEncoded()));
            x509Data.appendChild(x509Certificate);
        } catch (CertificateEncodingException e) {
            String message = "Error encoding certificate: " + certificate.getSubjectDN().getName();
            LOGGER.error(message, e);
            throw new RecipientCertificateException(message, e);
        }
        encryptedKey.appendChild(keyInfo);

        Element cipherData = document.createElement("denc:CipherData");
        Element cipherValue = document.createElement("denc:CipherValue");
        try {
            byte[] encryptedKeyBytes = CryptUtil.encryptRsa(key.getEncoded(), certificate);
            cipherValue.setTextContent(Base64.encodeBase64String(encryptedKeyBytes));
        } catch (GeneralSecurityException e) {
            String message = "Error encrypting secret key!";
            LOGGER.error(message, e);
            throw new EncryptionException(message, e);
        }
        cipherData.appendChild(cipherValue);
        encryptedKey.appendChild(cipherData);

        return encryptedKey;
    }

    protected Element createCipherData(SecretKey key, List<DataFile> dataFiles) throws CDOCException {
        Element cipherData = document.createElement("denc:CipherData");
        Element cipherValue = document.createElement("denc:CipherValue");

        byte[] dataToEncrypt;
        if (dataFiles.size() > 1) {
            dataToEncrypt = constructDataFilesXml(dataFiles);
        } else {
            dataToEncrypt = dataFiles.get(0).getContent();
        }
        try {
            int blockSize = key.getEncoded().length;
            byte[] iv = CryptUtil.generateIV(blockSize);
            byte[] encryptedDataFiles = CryptUtil.encryptAesCbc(dataToEncrypt, key, iv);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            byteArrayOutputStream.write(iv);
            byteArrayOutputStream.write(encryptedDataFiles);

            cipherValue.setTextContent(Base64.encodeBase64String(byteArrayOutputStream.toByteArray()));
        } catch (GeneralSecurityException | IOException e) {
            String message = "Error encrypting data files!";
            LOGGER.error(message, e);
            throw new EncryptionException(message, e);
        }

        cipherData.appendChild(cipherValue);
        return cipherData;
    }

    public byte[] constructDataFilesXml(List<DataFile> dataFiles) throws CDOCException {
        String xmlns = "http://www.sk.ee/DigiDoc/v1.3.0#";
        Document doc = XMLDocumentBuilder.createDocument();
        Element signedDoc = doc.createElement("SignedDoc");
        signedDoc.setAttribute("xmlns", xmlns);
        signedDoc.setAttribute("format", "DIGIDOC-XML");
        signedDoc.setAttribute("version", "1.3");

        int i = 0;
        for (DataFile dataFile : dataFiles) {
            Element datafile = doc.createElement("DataFile");
            datafile.setAttribute("ContentType", "EMBEDDED_BASE64");
            datafile.setAttribute("Filename", dataFile.getFileName());
            datafile.setAttribute("MimeType", "application/octet-stream");
            datafile.setAttribute("Size", String.valueOf(dataFile.getContent().length));
            datafile.setAttribute("Id", "D" + i++);
            datafile.setAttribute("xmlns", xmlns);
            datafile.setTextContent(Base64.encodeBase64String(dataFile.getContent()));
            signedDoc.appendChild(datafile);
        }

        doc.appendChild(signedDoc);
        return transformToXml(doc);
    }

    protected Element createEncryptionProperties(List<DataFile> dataFiles) {
        Element encryptionProperties = document.createElement("denc:EncryptionProperties");
        if (dataFiles.size() > 1)  {
            String ddocFileName = FilenameUtils.removeExtension(dataFiles.get(0).getFileName()) + ".ddoc";
            encryptionProperties.appendChild(createEncryptionProperty("Filename", ddocFileName));
        } else {
            encryptionProperties.appendChild(createEncryptionProperty("Filename", dataFiles.get(0).getFileName()));
        }
        encryptionProperties.appendChild(createEncryptionProperty("DocumentFormat", getEncDocXmlVersion()));
        encryptionProperties.appendChild(createEncryptionProperty("LibraryVersion", "cdoc4j|1.0"));
        int i = 0;
        for (DataFile dataFile : dataFiles) {
            String propertyValue = new StringBuilder()
                    .append(dataFile.getFileName())
                    .append("|")
                    .append(dataFile.getContent().length)
                    .append("|")
                    .append("application/octet-stream")
                    .append("|")
                    .append("D" + i++)
                    .toString();
            encryptionProperties.appendChild(createEncryptionProperty("orig_file", propertyValue));
        }
        return encryptionProperties;
    }

    protected Element createEncryptionProperty(String attributeValue, String propertyValue) {
        Element encryptionProperty = document.createElement("denc:EncryptionProperty");
        encryptionProperty.setAttribute("Name", attributeValue);
        encryptionProperty.setTextContent(propertyValue);
        return encryptionProperty;
    }

    protected byte[] transformToXml(Node node) throws XmlTransformException {
        try {
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.ENCODING, ENCODING);
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
            DOMSource source = new DOMSource(node);
            StringWriter strWriter = new StringWriter();
            StreamResult result = new StreamResult(strWriter);
            transformer.transform(source, result);
            return strWriter.getBuffer().toString().getBytes(ENCODING);
        } catch (TransformerException | UnsupportedEncodingException e) {
            String message = "Error transforming XML!";
            LOGGER.error(message, e);
            throw new XmlTransformException(message, e);
        }
    }

    protected String getEncDocXmlVersion() {
        return ENCDOC_XML_VERSION;
    }

} 
