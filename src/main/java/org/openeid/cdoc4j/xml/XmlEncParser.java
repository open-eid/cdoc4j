package org.openeid.cdoc4j.xml;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Base64;
import org.openeid.cdoc4j.*;
import org.openeid.cdoc4j.exception.CDOCException;
import org.openeid.cdoc4j.stream.ClosableBase64OutputStream;
import org.openeid.cdoc4j.stream.CustomOutputStreamWriter;
import org.openeid.cdoc4j.stream.DecryptionCipherOutputStream;
import org.openeid.cdoc4j.stream.PaddingRemovalOutputStream;
import org.openeid.cdoc4j.xml.exception.XmlParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;

public class XmlEncParser {

    private static final Logger LOGGER = LoggerFactory.getLogger(XmlEncParser.class);

    protected XMLStreamReader reader;

    public XmlEncParser(XMLStreamReader reader) {
        this.reader = reader;
    }

    public List<Recipient> getRecipients() throws XmlParseException {
        try {
            XmlEncParserUtil.goToElement(reader, "KeyInfo");
            return getAllRecipients();
        } catch (XMLStreamException  e) {
            throw formXmlParseException("Error parsing recipient(s) data from CDOC!", e);
        }
    }

    public void parseAndDecryptEncryptedDataPayload(OutputStream output, EncryptionMethod encryptionMethod, SecretKey key) throws CDOCException {
        try {
            XmlEncParserUtil.goToElement(reader, "CipherValue");
            byte[] IV = parseIVFromEncryptedFile(encryptionMethod.getBlockSize());

            try (OutputStream decryptStream = constructCipherOutputStream(output, key, IV);
                 ClosableBase64OutputStream base64DecoderStream = new ClosableBase64OutputStream(decryptStream, false);
                 CustomOutputStreamWriter outputWriter = new CustomOutputStreamWriter(base64DecoderStream)) {
                XmlEncParserUtil.readBase64DecodedAndEncryptedCharacters(reader, outputWriter, 1024);
            }
        } catch (XMLStreamException | IOException e) {
            throw formXmlParseException("Error parsing and base64 decoded and encrypted payload from CDOC!", e);
        }
    }

    public List<DataFile> parseAndDecryptDDOCPayload(final EncryptionMethod encryptionMethod, final SecretKey key, final DDOCParser ddocParser) throws XmlParseException {
        try {
            try (final PipedInputStream pipedInputStream = new PipedInputStream();
                 PipedOutputStream pipedOutputStream = new PipedOutputStream()) {

                pipedOutputStream.connect(pipedInputStream);

                XmlEncParserUtil.goToElement(reader, "CipherValue");

                Thread payloadDecryptionThread = formPayloadDecryptionThread(encryptionMethod, key, pipedOutputStream);
                Callable<List<DataFile>> ddocParserThread = formDDOCParserThread(pipedInputStream, ddocParser);

                try {
                    payloadDecryptionThread.start();
                    return ddocParserThread.call();
                } catch (Exception e) {
                    throw new IllegalStateException("Reading from pipe failed", e);
                }
            }

        } catch (XMLStreamException | IOException e) {
            throw formXmlParseException("Error parsing encrypted DDOC from CDOC!", e);
        }
    }

    public String getOriginalFileName() throws XmlParseException {
        try {
            XmlEncParserUtil.goToElement(reader, "EncryptionProperties");
            XmlEncParserUtil.goToElementWithAttributeValue(reader, "EncryptionProperty", "Name", "Filename");
            return XmlEncParserUtil.readCharacters(reader);
        } catch (XMLStreamException e) {
            throw formXmlParseException("Error parsing original file name from CDOC", e);
        }
    }

    protected List<Recipient> getAllRecipients() throws XmlParseException, XMLStreamException {
        List<Recipient> recipients = new ArrayList<>();
        while (XmlEncParserUtil.nextElementIs(reader, "EncryptedKey")) {
            String recipientCN = XmlEncParserUtil.getAttributeValue(reader, "Recipient");
            recipients.add(parseRecipient(recipientCN));
        }
        return recipients;
    }

    protected OutputStream constructCipherOutputStream(OutputStream output, SecretKey key, byte[] IV) {
        CBCBlockCipher cbcBlockCipher = new CBCBlockCipher(new AESEngine());
        KeyParameter keyParam = new KeyParameter(key.getEncoded());
        cbcBlockCipher.init(false, new ParametersWithIV(keyParam, IV));

        PaddedBufferedBlockCipher blockCipher = new PaddedBufferedBlockCipher(cbcBlockCipher, new PKCS7Padding());
        PaddingRemovalOutputStream paddingRemovalStream = new PaddingRemovalOutputStream(output);
        return new DecryptionCipherOutputStream(paddingRemovalStream, blockCipher, IV);
    }

    protected Recipient parseRecipient(String recipientCN) throws XmlParseException {
        X509Certificate certificate = extractCertificate();
        byte[] encryptedKey = extractEncryptedKey();
        return new RSARecipient(recipientCN, certificate, encryptedKey);
    }

    protected X509Certificate extractCertificate() throws XmlParseException {
        try {
            XmlEncParserUtil.goToElement(reader, "KeyInfo");
            XmlEncParserUtil.goToElement(reader, "X509Data");
            XmlEncParserUtil.goToElement(reader, "X509Certificate");
            String certificateBase64 = XmlEncParserUtil.readCharacters(reader);
            if (certificateBase64 == null) {
                throw new XmlParseException("Recipient's 'X509Certificate' element not found!");
            }
            byte[] certificateDer = Base64.decode(certificateBase64);
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certificateDer));
        } catch (XMLStreamException | CertificateException e) {
            throw formXmlParseException("Error parsing recipient's certificate from CDOC!", e);
        }
    }

    protected byte[] extractEncryptedKey() throws XmlParseException {
        try {
            XmlEncParserUtil.goToElement(reader, "CipherData");
            XmlEncParserUtil.goToElement(reader, "CipherValue");
            String encryptedKey = XmlEncParserUtil.readCharacters(reader);
            if (encryptedKey == null || encryptedKey == "") {
                throw new XmlParseException("'EncryptedKey' element (of the encrypted recipient's key) not found!");
            }
            return Base64.decode(encryptedKey);
        } catch (XMLStreamException e) {
            throw formXmlParseException("Error parsing encrypted key from CDOC!", e);
        }
    }

    protected XmlParseException formXmlParseException(String errorMessage) {
        LOGGER.error(errorMessage);
        return new XmlParseException(errorMessage);
    }

    protected XmlParseException formXmlParseException(String errorMessage, Exception exception) {
        LOGGER.error(errorMessage, exception);
        return new XmlParseException(errorMessage, exception);
    }

    private byte[] parseIVFromEncryptedFile(int IVLength) throws XMLStreamException {
        reader.next();
        int contentTotalLength = reader.getTextLength();

        int safeIVParsingBufferSize = contentTotalLength > IVLength * 2 ? IVLength * 2 : contentTotalLength;
        char[] buffer = new char[safeIVParsingBufferSize];
        reader.getTextCharacters(0, buffer, 0, safeIVParsingBufferSize);
        byte[] base64EncodedAndEncryptedFilePrefix = Base64.decode(new String(buffer).getBytes(StandardCharsets.UTF_8));
        return Arrays.copyOfRange(base64EncodedAndEncryptedFilePrefix, 0, IVLength);
    }

    private Callable<List<DataFile>> formDDOCParserThread(final PipedInputStream pipedInputStream, final DDOCParser ddocParser) {
        return new Callable<List<DataFile>>() {
                        @Override
                        public List<DataFile> call() throws XmlParseException {
                            try {
                                List<DataFile> parsedDataFiles = ddocParser.parseDataFiles(pipedInputStream);
                                ddocParser.close();
                                pipedInputStream.close();
                                return parsedDataFiles;
                            } catch (XmlParseException | IOException | XMLStreamException e) {
                                throw formXmlParseException("Failed to parse DDOC", e);
                            }
                        }
                    };
    }

    private Thread formPayloadDecryptionThread(final EncryptionMethod encryptionMethod, final SecretKey key, final PipedOutputStream pipedOutputStream) {
        return new Thread(new Runnable() {
                        @Override
                        public void run() {
                            try {
                                parseAndDecryptEncryptedDataPayload(pipedOutputStream, encryptionMethod, key);
                                pipedOutputStream.close();
                            } catch (IOException | CDOCException e) {
                                e.printStackTrace();
                            }
                        }
                    });
    }
}
