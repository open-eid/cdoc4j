package org.cdoc4j;

import java.security.cert.X509Certificate;

public class RSARecipient extends Recipient {

    public RSARecipient(String cn, X509Certificate certificate, byte[] encryptedKey) {
        super(cn, certificate, encryptedKey);
    }

}
