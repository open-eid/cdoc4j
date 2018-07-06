package org.openeid.cdoc4j.xml;

import com.ctc.wstx.stax.WstxOutputFactory;
import javanet.staxutils.IndentingXMLStreamWriter;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.CountingOutputStream;
import org.bouncycastle.util.encoders.Base64;
import org.openeid.cdoc4j.DataFile;
import org.openeid.cdoc4j.EncryptionMethod;
import org.openeid.cdoc4j.crypto.CertUtil;
import org.openeid.cdoc4j.crypto.CryptUtil;
import org.openeid.cdoc4j.crypto.PaddingUtil;
import org.openeid.cdoc4j.exception.CDOCException;
import org.openeid.cdoc4j.exception.EncryptionException;
import org.openeid.cdoc4j.exception.RecipientCertificateException;
import org.openeid.cdoc4j.stream.ClosableBase64OutputStream;
import org.openeid.cdoc4j.xml.exception.XmlTransformException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

public class XmlEncComposer {

    private static final Logger LOGGER = LoggerFactory.getLogger(XmlEncComposer.class);

    protected static final String DDOC_MIMETYPE = "http://www.sk.ee/DigiDoc/v1.3.0/digidoc.xsd";
    protected static final String ENCDOC_XML_VERSION = "ENCDOC-XML|1.0";

    protected static final String XML_ENCRYPTION_NAMESPACE_URL = "http://www.w3.org/2001/04/xmlenc#";
    protected static final String XML_ENCRYPTION_NAMESPACE_PREFIX = "denc";

    protected static final String XML_SIGNATURE_NAMESPACE_URL = "http://www.w3.org/2000/09/xmldsig#";
    protected static final String XML_SINGATURE_NAMESPACE_PREFIX = "ds";

    protected List<DataFile> dataFiles;
    protected EncryptionMethod encryptionMethod;
    protected SecretKey secretKey;
    protected List<X509Certificate> recipients;

    protected XMLStreamWriter writer;
    protected XMLOutputFactory factory;
    protected OutputStream output;

    public void constructXML(
            EncryptionMethod encryptionMethod,
            SecretKey secretKey,
            List<X509Certificate> recipients,
            List<DataFile> dataFiles,
            OutputStream output) throws CDOCException {

        this.dataFiles = dataFiles;
        this.encryptionMethod = encryptionMethod;
        this.secretKey = secretKey;
        this.recipients = recipients;
        this.output = output;
        factory = WstxOutputFactory.newInstance();

        try {
            writer = new IndentingXMLStreamWriter(factory.createXMLStreamWriter(output));

            writer.writeStartDocument(StandardCharsets.UTF_8.name(), "1.0");
            createEncryptedDataElement();
            writer.writeEndDocument();

        } catch (XMLStreamException e) {
            throw formXmlTransformException("Failed to construct XML", e);
        } finally {
            try {
                writer.flush();
                writer.close();
                output.close();

            } catch (XMLStreamException | IOException e) {
                throw new IllegalStateException("Failed to close XMLStreamWriter", e);
            }
        }
    }

    private void createEncryptedDataElement() throws XMLStreamException, CDOCException {
        writer.writeStartElement(xmlEncPrefix("EncryptedData"));
        writer.writeNamespace(XML_ENCRYPTION_NAMESPACE_PREFIX, XML_ENCRYPTION_NAMESPACE_URL);
        createMimeTypeAttribute();
        createEncryptionMethodElement(encryptionMethod.getURI());
        createKeyInfoElement();
        createCipherDataElement();
        createEncryptionPropertiesElement();
        writer.writeEndElement();
    }

    private void createMimeTypeAttribute() throws XMLStreamException {
        if (dataFiles.size() > 1) {
            LOGGER.debug("Multiple data files set - setting MimeType to: \"" + DDOC_MIMETYPE + "\"");
            writer.writeAttribute("MimeType", DDOC_MIMETYPE);
        } else {
            writer.writeAttribute("MimeType", "application/octet-stream");
        }
    }

    protected void createEncryptionMethodElement(String algorithmUrl) throws XMLStreamException {
        writer.writeEmptyElement(xmlEncPrefix("EncryptionMethod"));
        writer.writeAttribute("Algorithm", algorithmUrl);
    }

    private void createKeyInfoElement() throws XMLStreamException, CDOCException {
        writer.writeStartElement(xmlSigPrefix("KeyInfo"));
        writer.writeNamespace(XML_SINGATURE_NAMESPACE_PREFIX, XML_SIGNATURE_NAMESPACE_URL);

        for (X509Certificate certificate : recipients) {
            createRecipientEncryptedKeyElement(certificate);
        }

        writer.writeEndElement();
    }

    protected void createRecipientEncryptedKeyElement(X509Certificate certificate) throws XMLStreamException, CDOCException {
        writer.writeStartElement(xmlEncPrefix("EncryptedKey"));
        writer.writeAttribute("Recipient", CertUtil.getCN(certificate));
        createEncryptionMethodElement("http://www.w3.org/2001/04/xmlenc#rsa-1_5");
        createKeyInfoElement(certificate);
        createRecipientCipherDataElement(certificate);
        writer.writeEndElement();
    }

    protected void createKeyInfoElement(X509Certificate certificate) throws XMLStreamException, CDOCException {
        writer.writeStartElement(xmlSigPrefix("KeyInfo"));
        createX509DataElement(certificate);
        writer.writeEndElement();
    }

    protected void createX509DataElement(X509Certificate certificate) throws XMLStreamException, RecipientCertificateException {
        writer.writeStartElement(xmlSigPrefix("X509Data"));
        createX509CertificateElement(certificate);
        writer.writeEndElement();
    }

    private void createX509CertificateElement(X509Certificate certificate) throws XMLStreamException, RecipientCertificateException {
        writer.writeStartElement(xmlSigPrefix("X509Certificate"));

        try {
            writer.writeCharacters(Base64.toBase64String(certificate.getEncoded()));
        } catch (CertificateEncodingException e) {
            String message = "Error encoding certificate: " + certificate.getSubjectDN().getName();
            LOGGER.error(message, e);
            throw new RecipientCertificateException(message, e);
        }

        writer.writeEndElement();
    }

    private void createRecipientCipherDataElement(X509Certificate certificate) throws XMLStreamException, EncryptionException {
        writer.writeStartElement(xmlEncPrefix("CipherData"));
        createRecipientCipherValueElement(certificate);
        writer.writeEndElement();
    }

    private void createRecipientCipherValueElement(X509Certificate certificate) throws XMLStreamException, EncryptionException {
        writer.writeStartElement(xmlEncPrefix("CipherValue"));

        try {
            byte[] encryptedKeyBytes = CryptUtil.encryptRsa(secretKey.getEncoded(), certificate);
            writer.writeCharacters(Base64.toBase64String(encryptedKeyBytes));
        } catch (GeneralSecurityException e) {
            throw formEncryptionException("Error encrypting secret key!", e);
        }

        writer.writeEndElement();
    }

    private void createCipherDataElement() throws XMLStreamException, CDOCException {
        writer.writeStartElement(xmlEncPrefix("CipherData"));
        createdCipherValueElement();
        writer.writeEndElement();
    }

    protected void createdCipherValueElement() throws XMLStreamException, CDOCException {
        writer.writeStartElement(xmlEncPrefix("CipherValue"));
        beginCharacterWriting(writer);
        try {
            // flush everything that writer wrote prior writing directly to outputstream
            writer.flush();
        } catch (XMLStreamException e) {
            formXmlTransformException("Error on XML writer flush", e);
        }

        if (dataFiles.size() > 1) {
            LOGGER.debug("Multiple data files set - composing data files DDOC..");
            constructDataFilesXml();
        } else {
            encryptAndBase64EncodeSingleDataFile();
        }

        writer.writeEndElement();
    }

    protected void encryptAndBase64EncodeSingleDataFile() throws EncryptionException {
        int blockSize = secretKey.getEncoded().length;
        byte[] IV = CryptUtil.generateIV(blockSize);

        try (ClosableBase64OutputStream base64EncoderStream = new ClosableBase64OutputStream(output)) {
            base64EncoderStream.write(IV);
            encryptDataFile(base64EncoderStream, dataFiles.get(0), IV, blockSize);
        } catch (IOException e) {
            throw formEncryptionException("Failed to base64 encode single data file content", e);
        }
    }

    protected void encryptDataFile(OutputStream outputStream, DataFile dataFile, byte[] IV, int blockSize) throws EncryptionException {
        try (InputStream dataToEncrypt = dataFile.getContent()) {
            CryptUtil.encryptAesCbc(outputStream, dataToEncrypt, secretKey, IV, blockSize, dataFile.getSize());
        } catch (IOException | GeneralSecurityException e) {
            throw formEncryptionException("Error encrypting data file!", e);
        }
    }

    protected void constructDataFilesXml() throws CDOCException, XMLStreamException {
        int blockSize = secretKey.getEncoded().length;
        byte[] iv = CryptUtil.generateIV(blockSize);
        Cipher cipher = constructEncryptionCipher(iv);

        XMLStreamWriter ddocWriter = null;
        try (
            ClosableBase64OutputStream base64EncoderStream = new ClosableBase64OutputStream(output);
            CountingOutputStream cipherOutput = new CountingOutputStream(new CipherOutputStream(base64EncoderStream, cipher))
        ) {
            base64EncoderStream.write(iv);
            ddocWriter = new IndentingXMLStreamWriter(factory.createXMLStreamWriter(cipherOutput));
            constructAndEncryptDDOC(ddocWriter, cipherOutput);

            PaddingUtil.addX923Padding(cipherOutput, cipherOutput.getByteCount(), blockSize);
            PaddingUtil.addPkcs7Padding(cipherOutput, cipherOutput.getByteCount(), blockSize);
        } catch (IOException | EncryptionException | XMLStreamException e) {
            throw formXmlTransformException("Error transforming DDOC xml!", e);
        } finally {
            if (ddocWriter != null) {
                ddocWriter.close();
            }
        }
    }

    private Cipher constructEncryptionCipher(byte[] iv) throws EncryptionException {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            return cipher;
        } catch (GeneralSecurityException e) {
            throw new EncryptionException("Failed to construct AES CBC cipher", e);
        }
    }

    protected void constructAndEncryptDDOC(XMLStreamWriter streamWriter, OutputStream cipherOutputStream) throws XMLStreamException, EncryptionException {
        streamWriter.writeStartDocument(StandardCharsets.UTF_8.name(), "1.0");
        createSignedDocElement(cipherOutputStream, streamWriter);
        streamWriter.writeEndDocument();
    }

    private void createSignedDocElement(OutputStream cipherOutput, XMLStreamWriter innerWriter) throws XMLStreamException, EncryptionException {
        innerWriter.writeStartElement("SignedDoc");
        innerWriter.writeDefaultNamespace("http://www.sk.ee/DigiDoc/v1.3.0#");
        innerWriter.writeAttribute("format", "DIGIDOC-XML");
        innerWriter.writeAttribute("version", "1.3");

        for (int i = 0; i < dataFiles.size(); i++) {
            createDataFileElement(cipherOutput, innerWriter, i);
        }

        innerWriter.writeEndElement();
    }

    private void createDataFileElement(OutputStream cipherOutput, XMLStreamWriter innerWriter, int dataFileCounter) throws XMLStreamException, EncryptionException {
        DataFile dataFile = dataFiles.get(dataFileCounter);
        innerWriter.writeStartElement("DataFile");
        innerWriter.writeAttribute("ContentType", "EMBEDDED_BASE64");
        innerWriter.writeAttribute("Filename", dataFile.getName());
        innerWriter.writeAttribute("Id", "D" + dataFileCounter);
        innerWriter.writeAttribute("MimeType", "application/octet-stream");
        innerWriter.writeAttribute("Size", String.valueOf(dataFile.getSize()));

        try (
                ClosableBase64OutputStream base64Output = new ClosableBase64OutputStream(cipherOutput);
                InputStream inputStream = dataFile.getContent()
        ) {
            beginCharacterWriting(innerWriter);
            try {
                // flush everything that writer wrote prior writing directly to outputstream
                innerWriter.flush();
            } catch (XMLStreamException e) {
                formXmlTransformException("Error on XML writer flush", e);
            }
            IOUtils.copy(inputStream, base64Output, 1024);
        } catch (IOException e) {
            throw formEncryptionException("Failed to base64 encode DDOC content", e);
        }
        innerWriter.writeEndElement();
    }

    private void createEncryptionPropertiesElement() throws XMLStreamException {
        writer.writeStartElement(xmlEncPrefix("EncryptionProperties"));

        if (dataFiles.size() > 1)  {
            String ddocFileName = FilenameUtils.removeExtension(dataFiles.get(0).getName()) + ".ddoc";
            createEncryptionPropertyElement("Filename", ddocFileName);
        } else {
            createEncryptionPropertyElement("Filename", dataFiles.get(0).getName());
        }

        createEncryptionPropertyElement("DocumentFormat", getEncDocXmlVersion());
        createEncryptionPropertyElement("LibraryVersion", "cdoc4j|1.0");

        int fileCount = 0;
        for (DataFile dataFile : dataFiles) {
            String propertyValue = new StringBuilder()
                    .append(dataFile.getName())
                    .append("|")
                    .append(dataFile.getSize())
                    .append("|")
                    .append("application/octet-stream")
                    .append("|")
                    .append("D" + fileCount++)
                    .toString();
            createEncryptionPropertyElement("orig_file", propertyValue);
        }

        writer.writeEndElement();
    }

    protected void createEncryptionPropertyElement(String attributeValue, String propertyValue) throws XMLStreamException {
        writer.writeStartElement(xmlEncPrefix("EncryptionProperty"));
        writer.writeAttribute("Name", attributeValue);
        writer.writeCharacters(propertyValue);
        writer.writeEndElement();
    }

    protected String getEncDocXmlVersion() {
        return ENCDOC_XML_VERSION;
    }

    protected String xmlEncPrefix(String elementName) {
        return XML_ENCRYPTION_NAMESPACE_PREFIX + ":" + elementName;
    }

    protected String xmlSigPrefix(String elementName) {
        return XML_SINGATURE_NAMESPACE_PREFIX + ":" + elementName;
    }

    protected EncryptionException formEncryptionException(String errorMessage, Exception exception) {
        LOGGER.error(errorMessage, exception);
        return new EncryptionException(errorMessage, exception);
    }

    protected XmlTransformException formXmlTransformException(String errorMessage, Exception exception) {
        LOGGER.error(errorMessage, exception);
        return new XmlTransformException(errorMessage, exception);
    }

    // Necessary when writing raw characters, otherwise content is written inside current element starting tag
    private void beginCharacterWriting(XMLStreamWriter streamWriter) throws XMLStreamException {
        streamWriter.writeCharacters("");
    }
}
