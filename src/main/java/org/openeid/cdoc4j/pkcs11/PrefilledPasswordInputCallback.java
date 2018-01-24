package org.openeid.cdoc4j.pkcs11;

public class PrefilledPasswordInputCallback {

    private final char[] password;

    public PrefilledPasswordInputCallback(char[] password) {
        this.password = password;
    }

    public char[] getPassword() {
        return password;
    }

}
