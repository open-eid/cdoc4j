package org.cdoc4j.xml;

import org.cdoc4j.ECRecipient;
import org.cdoc4j.Recipient;
import org.cdoc4j.xml.exception.XmlParseException;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;

public class XmlEnc11Parser extends XmlEncParser {

    private static final Logger LOGGER = LoggerFactory.getLogger(XmlEnc11Parser.class);

    public XmlEnc11Parser(Document document) throws XmlParseException {
        super(document);
    }

    @Override
    protected Recipient getRecipient(Node recipientNode) throws XmlParseException {
        try {
            XPathExpression expression = xPath.compile("EncryptionMethod");
            Node encryptionMethod = (Node) expression.evaluate(recipientNode, XPathConstants.NODE);
            String algorithm = encryptionMethod.getAttributes().getNamedItem("Algorithm").getTextContent();

            if (algorithm.equals("http://www.w3.org/2001/04/xmlenc#rsa-1_5")) {
                return super.getRecipient(recipientNode);
            } else if (algorithm.equals("http://www.w3.org/2001/04/xmlenc#kw-aes256")) {
                return getECRecipient(recipientNode);
            } else {
                String message = "Recipient has unknown encryption method algorithm: " + algorithm;
                LOGGER.error(message);
                throw new XmlParseException(message);
            }
        } catch (XPathExpressionException e) {
            String message = "Error parsing encrypted method algorithm from CDOC";
            LOGGER.error(message, e);
            throw new XmlParseException(message, e);
        }
    }

    protected Recipient getECRecipient(Node recipientNode) throws XmlParseException {
        try {
            String cn = extractCN(recipientNode);

            XPathExpression expression = xPath.compile("KeyInfo/AgreementMethod/KeyDerivationMethod/ConcatKDFParams");
            Node concatKDFParams = (Node) expression.evaluate(recipientNode, XPathConstants.NODE);
            byte algorithmId[] = Hex.decode(concatKDFParams.getAttributes().getNamedItem("AlgorithmID").getTextContent());
            byte partyUInfo[] = Hex.decode(concatKDFParams.getAttributes().getNamedItem("PartyUInfo").getTextContent());
            byte partyVInfo[] = Hex.decode(concatKDFParams.getAttributes().getNamedItem("PartyVInfo").getTextContent());

            algorithmId = Arrays.copyOfRange(algorithmId, 1, algorithmId.length);
            partyUInfo = Arrays.copyOfRange(partyUInfo, 1, partyUInfo.length);
            partyVInfo = Arrays.copyOfRange(partyVInfo, 1, partyVInfo.length);

            byte[] encryptedKey = extractEncryptedKey(recipientNode);
            X509Certificate certificate = extractECCertificate(recipientNode);

            expression = xPath.compile("KeyInfo/AgreementMethod/OriginatorKeyInfo/KeyValue/ECKeyValue/PublicKey");
            Node publicKey = (Node) expression.evaluate(recipientNode, XPathConstants.NODE);

            ECNamedCurveParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec("secp384r1");
            ECParameterSpec secp384r1 = new ECNamedCurveSpec(ecParameterSpec.getName(), ecParameterSpec.getCurve(),
                    ecParameterSpec.getG(), ecParameterSpec.getN(), ecParameterSpec.getH());
            ECPoint point = ECPointUtil.decodePoint(secp384r1.getCurve(), Base64.decodeBase64(publicKey.getTextContent()));
            KeyFactory ecKeyFactory = KeyFactory.getInstance("EC");
            ECPublicKey ecPublicKey = (ECPublicKey) ecKeyFactory.generatePublic(new ECPublicKeySpec(point, secp384r1));

            return new ECRecipient(cn, certificate, encryptedKey, ecPublicKey, algorithmId, partyUInfo, partyVInfo);
        } catch (Exception e) {
            String message = "Error parsing recipient data from CDOC!";
            LOGGER.error(message, e);
            throw new XmlParseException(message, e);
        }
    }

    protected X509Certificate extractECCertificate(Node recipientNode) throws XPathExpressionException, CertificateException {
        XPathExpression expression = xPath.compile("KeyInfo/AgreementMethod/RecipientKeyInfo/X509Data/X509Certificate");
        Node certificateBase64 = (Node) expression.evaluate(recipientNode, XPathConstants.NODE);
        byte[] certificateDer = Base64.decodeBase64(certificateBase64.getTextContent());
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certificateDer));
        return certificate;
    }

}
