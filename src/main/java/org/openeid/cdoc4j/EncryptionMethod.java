package org.openeid.cdoc4j;

public enum EncryptionMethod {
    AES_128_CBC("http://www.w3.org/2001/04/xmlenc#aes128-cbc", 16),
    AES_256_GCM("http://www.w3.org/2009/xmlenc11#aes256-gcm", 12);

    private String uri;
    private int blockSize;

    EncryptionMethod(String uri, int blockSize) {
        this.uri = uri;
        this.blockSize = blockSize;
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

    public int getBlockSize() {
        return blockSize;
    }
}
