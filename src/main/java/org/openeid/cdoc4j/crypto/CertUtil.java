package org.openeid.cdoc4j.crypto;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.openeid.cdoc4j.exception.RecipientCertificateException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class CertUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(CertUtil.class);

    private CertUtil() {}

    public static String getCN(X509Certificate certificate) throws RecipientCertificateException {
        try {
            X500Name x500name = new JcaX509CertificateHolder(certificate).getSubject();
            RDN cn = x500name.getRDNs(BCStyle.CN)[0];
            return cn.getFirst().getValue().toString();
        } catch (CertificateException e) {
            String message = "Error extracting CN from certificate: " + certificate.getSubjectX500Principal().getName();
            LOGGER.error(message, e);
            throw new RecipientCertificateException(message, e);
        }
    }

} 
