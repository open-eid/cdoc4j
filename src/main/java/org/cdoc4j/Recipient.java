package org.cdoc4j;

import java.security.cert.X509Certificate;

public abstract class Recipient {

    private String cn;
    private X509Certificate certificate;
    private byte[] encryptedKey;

    public Recipient(String cn, X509Certificate certificate, byte[] encryptedKey) {
        this.cn = cn;
        this.certificate = certificate;
        this.encryptedKey = encryptedKey;
    }

    public byte[] getEncryptedKey() {
        return encryptedKey;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public String getCN() {
        return cn;
    }
}
