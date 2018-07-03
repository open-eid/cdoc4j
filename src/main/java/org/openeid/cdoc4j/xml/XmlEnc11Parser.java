package org.openeid.cdoc4j.xml;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.openeid.cdoc4j.ECRecipient;
import org.openeid.cdoc4j.Recipient;
import org.openeid.cdoc4j.stream.DecryptionCipherOutputStream;
import org.openeid.cdoc4j.xml.exception.XmlParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class XmlEnc11Parser extends XmlEncParser {

    private static final Logger LOGGER = LoggerFactory.getLogger(XmlEnc11Parser.class);

    public XmlEnc11Parser(XMLStreamReader reader) {
        super(reader);
    }

    @Override
    protected OutputStream constructCipherOutputStream(OutputStream output, SecretKey key, byte[] IV) {
        KeyParameter secretKey = new KeyParameter(key.getEncoded());
        AEADBlockCipher cipher = new GCMBlockCipher(new AESEngine());
        cipher.init(false, new AEADParameters(secretKey, 128, IV));
        return new DecryptionCipherOutputStream(output, cipher, IV);
    }

    @Override
    protected Recipient parseRecipient(String recipientCN) throws XmlParseException {
        try {
            XmlEncParserUtil.goToElement(reader, "EncryptionMethod");
            String algorithm = XmlEncParserUtil.getAttributeValue(reader, "Algorithm");

            if (algorithm.equals("http://www.w3.org/2001/04/xmlenc#rsa-1_5")) {
                return super.parseRecipient(recipientCN);
            } else if (algorithm.equals("http://www.w3.org/2001/04/xmlenc#kw-aes256")) {
                return parseECRecipient(recipientCN);
            } else {
                throw formXmlParseException("Recipient has an unknown encryption method algorithm: " + algorithm);
            }
        } catch (XMLStreamException e) {
            String message = "Error parsing encrypted method algorithm from CDOC";
            LOGGER.error(message, e);
            throw new XmlParseException(message, e);
        }
    }

    private Recipient parseECRecipient(String recipientCN) throws XmlParseException {
        try {
            XmlEncParserUtil.goToElement(reader, "KeyInfo");
            XmlEncParserUtil.goToElement(reader, "AgreementMethod");
            XmlEncParserUtil.goToElement(reader, "KeyDerivationMethod");
            XmlEncParserUtil.goToElement(reader, "ConcatKDFParams");

            byte algorithmId[] = Hex.decode(XmlEncParserUtil.getAttributeValue(reader, "AlgorithmID"));
            byte partyUInfo[] = Hex.decode(XmlEncParserUtil.getAttributeValue(reader, "PartyUInfo"));
            byte partyVInfo[] = Hex.decode(XmlEncParserUtil.getAttributeValue(reader, "PartyVInfo"));

            algorithmId = Arrays.copyOfRange(algorithmId, 1, algorithmId.length);
            partyUInfo = Arrays.copyOfRange(partyUInfo, 1, partyUInfo.length);
            partyVInfo = Arrays.copyOfRange(partyVInfo, 1, partyVInfo.length);

            XmlEncParserUtil.goToElement(reader, "OriginatorKeyInfo");
            XmlEncParserUtil.goToElement(reader, "KeyValue");
            XmlEncParserUtil.goToElement(reader, "ECKeyValue");
            XmlEncParserUtil.goToElement(reader, "PublicKey");

            ECPublicKey ecPublicKey = parseECPublicKey();
            X509Certificate certificate = extractECCertificate();
            byte[] encryptedKey = extractEncryptedKey();

            return new ECRecipient(recipientCN, certificate, encryptedKey, ecPublicKey, algorithmId, partyUInfo, partyVInfo);
        } catch (NoSuchAlgorithmException | XMLStreamException | InvalidKeySpecException e) {
            throw formXmlParseException("Error parsing recipient data from CDOC!", e);
        }
    }

    private ECPublicKey parseECPublicKey() throws XMLStreamException, NoSuchAlgorithmException, InvalidKeySpecException {
        String publicKey = XmlEncParserUtil.readCharacters(reader);
        ECNamedCurveParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec("secp384r1");
        ECParameterSpec secp384r1 = new ECNamedCurveSpec(
                ecParameterSpec.getName(),
                ecParameterSpec.getCurve(),
                ecParameterSpec.getG(),
                ecParameterSpec.getN(),
                ecParameterSpec.getH());

        ECPoint point = ECPointUtil.decodePoint(secp384r1.getCurve(), Base64.decode(publicKey));
        KeyFactory ecKeyFactory = KeyFactory.getInstance("EC");
        return (ECPublicKey) ecKeyFactory.generatePublic(new ECPublicKeySpec(point, secp384r1));
    }

    private X509Certificate extractECCertificate() throws XmlParseException {
        try {
            XmlEncParserUtil.goToElement(reader, "RecipientKeyInfo");
            XmlEncParserUtil.goToElement(reader, "X509Data");
            XmlEncParserUtil.goToElement(reader, "X509Certificate");

            String certificateBase64 = XmlEncParserUtil.readCharacters(reader);
            return formX509Certificate(Base64.decode(certificateBase64));
        } catch (XMLStreamException e) {
            throw formXmlParseException("Error parsing recipient's certificate from CDOC!", e);
        }
    }

    private X509Certificate formX509Certificate(byte[] certificate) throws XmlParseException {
        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(certificate)) {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certFactory.generateCertificate(inputStream);
        } catch (IOException | CertificateException e) {
            throw formXmlParseException("Error forming X509Certificate from parsed content!", e);
        }
    }
}
