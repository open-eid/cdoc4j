package org.openeid.cdoc4j.xml;

import org.bouncycastle.util.encoders.Base64;
import org.openeid.cdoc4j.EncryptionMethod;
import org.openeid.cdoc4j.RSARecipient;
import org.openeid.cdoc4j.Recipient;
import org.openeid.cdoc4j.xml.exception.XmlParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.xpath.*;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class XmlEncParser {

    private static final Logger LOGGER = LoggerFactory.getLogger(XmlEncParser.class);

    private static final String DDOC_MIMETYPE = "http://www.sk.ee/DigiDoc/v1.3.0/digidoc.xsd";

    protected Document document;

    protected XPath xPath;

    public XmlEncParser(Document document) throws XmlParseException {
        this.document = document;
        xPath = XPathFactory.newInstance().newXPath();
    }

    public List<Recipient> getRecipients() throws XmlParseException {
        try {
            List <Recipient> recipients = new ArrayList<>();
            XPathExpression expression = xPath.compile("/EncryptedData/KeyInfo/EncryptedKey");
            NodeList recipientNodes = (NodeList) expression.evaluate(document, XPathConstants.NODESET);
            for (int i = 0; i < recipientNodes.getLength(); i++) {
                Node recipientNode = recipientNodes.item(i);
                recipients.add(getRecipient(recipientNode));
            }
            return recipients;
        } catch (XPathExpressionException e) {
            String message = "Error parsing recipient(s) data from CDOC!";
            LOGGER.error(message, e);
            throw new XmlParseException(message, e);
        }
    }

    public byte[] getEncryptedPayload() throws XmlParseException {
        try {
            XPathExpression expression = xPath.compile("/EncryptedData/CipherData/CipherValue");
            Node cipherValue = (Node) expression.evaluate(document, XPathConstants.NODE);
            if (cipherValue == null) {
                throw new XmlParseException("'CipherValue' element (of the encrypted payload) not found!");
            }
            byte[] encryptedPayload = Base64.decode(cipherValue.getTextContent());
            return encryptedPayload;
        } catch (XPathExpressionException e) {
            String message = "Error parsing encrypted payload from CDOC!";
            LOGGER.error(message, e);
            throw new XmlParseException(message, e);
        }
    }

    public EncryptionMethod getEncryptionMethod() throws XmlParseException {
        try {
            XPathExpression expression = xPath.compile("/EncryptedData/EncryptionMethod");
            Node encryptionMethod = (Node) expression.evaluate(document, XPathConstants.NODE);
            if (encryptionMethod == null) {
                throw new XmlParseException("'EncryptionMethod' element not found!");
            }
            String encrytionMethodUri = encryptionMethod.getAttributes().getNamedItem("Algorithm").getTextContent();
            return EncryptionMethod.fromURI(encrytionMethodUri);
        } catch (XPathExpressionException e) {
            String message = "Error parsing encrypted method from CDOC";
            LOGGER.error(message, e);
            throw new XmlParseException(message, e);
        }
    }

    public boolean encryptedPayloadIsDDOC() throws XmlParseException {
        try {
            XPathExpression expression = xPath.compile("/EncryptedData");
            Node encryptedData = (Node) expression.evaluate(document, XPathConstants.NODE);
            return DDOC_MIMETYPE.equals(encryptedData.getAttributes().getNamedItem("MimeType").getTextContent());
        } catch (XPathExpressionException e) {
            String message = "Error parsing recipient(s) data from CDOC!";
            LOGGER.error(message, e);
            throw new XmlParseException(message, e);
        }
    }

    public String getOriginalFileName() throws XmlParseException {
        try {
            XPathExpression expression = xPath.compile("/EncryptedData/EncryptionProperties/EncryptionProperty[@Name=\"Filename\"]");
            Node fileName = (Node) expression.evaluate(document, XPathConstants.NODE);
            if (fileName == null) {
                throw new XmlParseException("'Filename' EncryptionProperty not found!");
            }
            return fileName.getTextContent();
        } catch (XPathExpressionException e) {
            String message = "Error parsing encrypted method from CDOC";
            LOGGER.error(message, e);
            throw new XmlParseException(message, e);
        }
    }

    protected Recipient getRecipient(Node recipientNode) throws XmlParseException {
        String cn = extractCN(recipientNode);
        X509Certificate certificate = extractCertificate(recipientNode);
        byte[] encryptedKey = extractEncryptedKey(recipientNode);
        return new RSARecipient(cn, certificate, encryptedKey);
    }

    protected String extractCN(Node recipientNode) {
        return recipientNode.getAttributes().getNamedItem("Recipient").getTextContent();
    }

    protected X509Certificate extractCertificate(Node recipientNode) throws XmlParseException {
        try {
            XPathExpression expression = xPath.compile("KeyInfo/X509Data/X509Certificate");
            Node certificateBase64 = (Node) expression.evaluate(recipientNode, XPathConstants.NODE);
            if (certificateBase64 == null) {
                throw new XmlParseException("Recipient's 'X509Certificate' element not found!");
            }
            byte[] certificateDer = Base64.decode(certificateBase64.getTextContent());
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certificateDer));
            return certificate;
        } catch (XPathExpressionException | CertificateException e) {
            String message = "Error parsing recipient's certificate from CDOC!";
            LOGGER.error(message, e);
            throw new XmlParseException(message, e);
        }
    }

    protected byte[] extractEncryptedKey(Node recipientNode) throws XmlParseException {
        try {
            XPathExpression expression = xPath.compile("CipherData/CipherValue");
            Node encryptedKey = (Node) expression.evaluate(recipientNode, XPathConstants.NODE);
            if (encryptedKey == null) {
                throw new XmlParseException("'CipherValue' element (of the encrypted recipient's key) not found!");
            }
            return Base64.decode(encryptedKey.getTextContent());
        } catch (XPathExpressionException e) {
            String message = "Error parsing encrypted key from CDOC!";
            LOGGER.error(message, e);
            throw new XmlParseException(message, e);
        }
    }

} 
