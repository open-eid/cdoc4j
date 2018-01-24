package org.openeid.cdoc4j.crypto;

import org.openeid.cdoc4j.exception.RecipientCertificateException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.security.cert.X509Certificate;

public class CertUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(CertUtil.class);

    private CertUtil() {}

    public static String getCN(X509Certificate certificate) throws RecipientCertificateException {
        return getRdn(certificate, "CN");
    }

    private static String getRdn(X509Certificate certificate, String input) throws RecipientCertificateException {
        try {
            LdapName ln = new LdapName(certificate.getSubjectDN().getName());
            for (Rdn rdn : ln.getRdns()) {
                if (input.equalsIgnoreCase(rdn.getType())) {
                    return rdn.getValue().toString();
                }
            }
            return null;
        } catch (InvalidNameException e) {
            String message = "Error extracting CN from certificate: " + certificate.getSubjectDN().getName();
            LOGGER.error(message, e);
            throw new RecipientCertificateException(message, e);
        }
    }

} 
