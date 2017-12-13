package org.cdoc4j;

public enum EncryptionMethod {
    AES_128_CBC("http://www.w3.org/2001/04/xmlenc#aes128-cbc"),
    AES_256_GCM("http://www.w3.org/2009/xmlenc11#aes256-gcm");

    private String uri;

    EncryptionMethod(String uri) {
        this.uri = uri;
    }

    public static EncryptionMethod fromURI(String uri) {
        for (EncryptionMethod e : values()) {
            if (e.uri.equals(uri))
                return e;
        }
        return null;
    }

    public String getURI() {
        return uri;
    }

}
