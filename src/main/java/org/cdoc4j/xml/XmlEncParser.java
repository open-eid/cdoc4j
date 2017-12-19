package org.cdoc4j.xml;

import org.cdoc4j.EncryptionMethod;
import org.cdoc4j.RSARecipient;
import org.cdoc4j.Recipient;
import org.cdoc4j.xml.exception.XmlParseException;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class XmlEncParser {

    private static final Logger LOGGER = LoggerFactory.getLogger(XmlEncParser.class);

    private static final List<String> DDOC_MIMETYPES = Arrays.asList("http://www.sk.ee/DigiDoc/v1.3.0/digidoc.xsd", "http://www.sk.ee/DigiDoc/v1.3.0#");

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
            byte[] encryptedPayload = Base64.decodeBase64(cipherValue.getTextContent());
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
            return DDOC_MIMETYPES.contains(encryptedData.getAttributes().getNamedItem("MimeType").getTextContent());
        } catch (XPathExpressionException e) {
            String message = "Error parsing recipient(s) data from CDOC!";
            LOGGER.error(message, e);
            throw new XmlParseException(message, e);
        }
    }

    public String getOriginalFileName() throws XmlParseException {
        try {
            XPathExpression expression = xPath.compile("/EncryptedData/EncryptionProperties/EncryptionProperty[@Name=\"Filename\"]");
            Node encryptionMethod = (Node) expression.evaluate(document, XPathConstants.NODE);
            return encryptionMethod.getTextContent();
        } catch (XPathExpressionException e) {
            String message = "Error parsing encrypted method from CDOC";
            LOGGER.error(message, e);
            throw new XmlParseException(message, e);
        }
    }

    protected Recipient getRecipient(Node recipientNode) throws XmlParseException {
        try {
            String cn = extractCN(recipientNode);
            X509Certificate certificate = extractCertificate(recipientNode);
            byte[] encryptedKey = extractEncryptedKey(recipientNode);
            return new RSARecipient(cn, certificate, encryptedKey);
        } catch (Exception e) {
            String message = "Error parsing recipient data from CDOC!";
            LOGGER.error(message, e);
            throw new XmlParseException(message, e);
        }
    }

    protected String extractCN(Node recipientNode) {
        return recipientNode.getAttributes().getNamedItem("Recipient").getTextContent();
    }

    protected X509Certificate extractCertificate(Node recipientNode) throws XPathExpressionException, CertificateException {
        XPathExpression expression = xPath.compile("KeyInfo/X509Data/X509Certificate");
        Node certificateBase64 = (Node) expression.evaluate(recipientNode, XPathConstants.NODE);
        byte[] certificateDer = Base64.decodeBase64(certificateBase64.getTextContent());
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certificateDer));
        return certificate;
    }

    protected byte[] extractEncryptedKey(Node recipientNode) throws XPathExpressionException {
        XPathExpression expression = xPath.compile("CipherData/CipherValue");
        Node encryptedKey = (Node) expression.evaluate(recipientNode, XPathConstants.NODE);
        return Base64.decodeBase64(encryptedKey.getTextContent());
    }

} 
